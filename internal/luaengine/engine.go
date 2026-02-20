package luaengine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// ErrLuaTimeout is returned when Lua script exceeds execution time limit.
var ErrLuaTimeout = errors.New("lua script exceeded execution time limit")

// DefaultTimeout is the default execution time limit per Lua evaluation.
const DefaultTimeout = 5 * time.Second

// CompiledPolicy holds a pre-compiled Lua script for reuse across calls.
type CompiledPolicy struct {
	proto *lua.FunctionProto
	mu    sync.Mutex
}

// Compile parses and compiles a Lua script. The result can be reused for many Evaluate calls.
func Compile(script string) (*CompiledPolicy, error) {
	L := lua.NewState(lua.Options{SkipOpenLibs: true})
	defer L.Close()

	fn, err := L.LoadString(script)
	if err != nil {
		return nil, fmt.Errorf("lua compile error: %w", err)
	}
	return &CompiledPolicy{proto: fn.Proto}, nil
}

// Evaluate runs the compiled Lua policy against the given claims and token type.
// It returns nil if the script passes, or an error describing the policy violation.
func (cp *CompiledPolicy) Evaluate(claims map[string]any, tokenType string) error {
	return cp.EvaluateWithTimeout(claims, tokenType, DefaultTimeout)
}

// EvaluateWithTimeout runs with a custom execution timeout.
func (cp *CompiledPolicy) EvaluateWithTimeout(claims map[string]any, tokenType string, timeout time.Duration) error {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	L := lua.NewState(lua.Options{SkipOpenLibs: true})
	defer L.Close()

	// Use context for timeout/cancellation (gopher-lua supports context-based cancellation)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	L.SetContext(ctx)

	// Open only safe libraries (no os, io, debug, package)
	openSafeLibs(L)

	// Set global variables
	L.SetGlobal("token_type", lua.LString(tokenType))
	L.SetGlobal("claims", mapToLTable(L, claims))

	// Track rejection error
	var policyErr error

	// Register helper functions
	L.SetGlobal("has", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		_, ok := claims[key]
		L.Push(lua.LBool(ok))
		return 1
	}))

	L.SetGlobal("get", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		val, ok := claims[key]
		if !ok {
			L.Push(lua.LNil)
			return 1
		}
		L.Push(goToLua(L, val))
		return 1
	}))

	L.SetGlobal("require_claim", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		if _, ok := claims[key]; !ok {
			policyErr = fmt.Errorf("lua policy: required claim missing: %s", key)
			L.RaiseError("%s", policyErr.Error())
		}
		return 0
	}))

	L.SetGlobal("require_value", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		expected := L.Get(2)
		val, ok := claims[key]
		if !ok {
			policyErr = fmt.Errorf("lua policy: claim %s missing for value check", key)
			L.RaiseError("%s", policyErr.Error())
			return 0
		}
		if !luaValuesMatch(val, expected) {
			policyErr = fmt.Errorf("lua policy: claim %s value mismatch", key)
			L.RaiseError("%s", policyErr.Error())
		}
		return 0
	}))

	L.SetGlobal("require_one_of", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		tbl := L.CheckTable(2)
		val, ok := claims[key]
		if !ok {
			policyErr = fmt.Errorf("lua policy: claim %s missing for one_of check", key)
			L.RaiseError("%s", policyErr.Error())
			return 0
		}
		found := false
		tbl.ForEach(func(_ lua.LValue, v lua.LValue) {
			if luaValuesMatch(val, v) {
				found = true
			}
		})
		if !found {
			policyErr = fmt.Errorf("lua policy: claim %s value not in allowed set", key)
			L.RaiseError("%s", policyErr.Error())
		}
		return 0
	}))

	L.SetGlobal("reject", L.NewFunction(func(L *lua.LState) int {
		msg := L.OptString(1, "rejected by lua policy")
		policyErr = fmt.Errorf("lua policy: %s", msg)
		L.RaiseError("%s", policyErr.Error())
		return 0
	}))

	// Type-check helpers
	for _, tc := range []struct {
		name string
		fn   func(any) bool
	}{
		{"is_string", func(v any) bool { _, ok := v.(string); return ok }},
		{"is_number", func(v any) bool {
			switch v.(type) {
			case float64, float32, int, int32, int64:
				return true
			}
			return false
		}},
		{"is_bool", func(v any) bool { _, ok := v.(bool); return ok }},
		{"is_table", func(v any) bool {
			switch v.(type) {
			case map[string]any, []any:
				return true
			}
			return false
		}},
	} {
		check := tc.fn
		L.SetGlobal(tc.name, L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			val, ok := claims[key]
			if !ok {
				L.Push(lua.LFalse)
				return 1
			}
			L.Push(lua.LBool(check(val)))
			return 1
		}))
	}

	// Execute compiled script
	fn := L.NewFunctionFromProto(cp.proto)
	L.Push(fn)
	err := L.PCall(0, lua.MultRet, nil)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return ErrLuaTimeout
		}
		if policyErr != nil {
			return policyErr
		}
		return fmt.Errorf("lua policy error: %w", err)
	}
	return policyErr
}

// openSafeLibs opens only safe standard libraries.
func openSafeLibs(L *lua.LState) {
	for _, pair := range []struct {
		name string
		fn   lua.LGFunction
	}{
		{lua.LoadLibName, lua.OpenBase},
		{lua.TabLibName, lua.OpenTable},
		{lua.StringLibName, lua.OpenString},
		{lua.MathLibName, lua.OpenMath},
	} {
		L.Push(L.NewFunction(pair.fn))
		L.Push(lua.LString(pair.name))
		L.Call(1, 0)
	}
	// Remove dangerous base functions that could escape the sandbox.
	L.SetGlobal("dofile", lua.LNil)
	L.SetGlobal("loadfile", lua.LNil)
	L.SetGlobal("load", lua.LNil)
	L.SetGlobal("loadstring", lua.LNil)
}

// mapToLTable converts a Go map to a Lua table.
func mapToLTable(L *lua.LState, m map[string]any) *lua.LTable {
	tbl := L.NewTable()
	for k, v := range m {
		tbl.RawSetString(k, goToLua(L, v))
	}
	return tbl
}

// goToLua converts a Go value to a Lua value.
func goToLua(L *lua.LState, v any) lua.LValue {
	switch val := v.(type) {
	case string:
		return lua.LString(val)
	case bool:
		return lua.LBool(val)
	case float64:
		return lua.LNumber(val)
	case float32:
		return lua.LNumber(val)
	case int:
		return lua.LNumber(val)
	case int32:
		return lua.LNumber(val)
	case int64:
		return lua.LNumber(val)
	case map[string]any:
		return mapToLTable(L, val)
	case []any:
		tbl := L.NewTable()
		for i, item := range val {
			tbl.RawSetInt(i+1, goToLua(L, item))
		}
		return tbl
	case []string:
		tbl := L.NewTable()
		for i, item := range val {
			tbl.RawSetInt(i+1, lua.LString(item))
		}
		return tbl
	case nil:
		return lua.LNil
	default:
		return lua.LString(fmt.Sprintf("%v", val))
	}
}

// luaValuesMatch checks if a Go claim value matches a Lua expected value.
func luaValuesMatch(goVal any, luaVal lua.LValue) bool {
	switch lv := luaVal.(type) {
	case lua.LString:
		if s, ok := goVal.(string); ok {
			return s == string(lv)
		}
	case lua.LNumber:
		switch gv := goVal.(type) {
		case float64:
			return gv == float64(lv)
		case float32:
			return float64(gv) == float64(lv)
		case int:
			return float64(gv) == float64(lv)
		case int64:
			return float64(gv) == float64(lv)
		}
	case *lua.LNilType:
		return goVal == nil
	case lua.LBool:
		if b, ok := goVal.(bool); ok {
			return b == bool(lv)
		}
	}
	return false
}
