let wasm_bindgen = (function(exports) {
    let script_src;
    if (typeof document !== 'undefined' && document.currentScript !== null) {
        script_src = new URL(document.currentScript.src, location.href).toString();
    }

    function __wbg_get_imports() {
        const import0 = {
            __proto__: null,
            __wbg___wbindgen_debug_string_0bc8482c6e3508ae: function(arg0, arg1) {
                const ret = debugString(arg1);
                const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
                const len1 = WASM_VECTOR_LEN;
                getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
                getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
            },
            __wbg___wbindgen_is_function_0095a73b8b156f76: function(arg0) {
                const ret = typeof(arg0) === 'function';
                return ret;
            },
            __wbg___wbindgen_is_object_5ae8e5880f2c1fbd: function(arg0) {
                const val = arg0;
                const ret = typeof(val) === 'object' && val !== null;
                return ret;
            },
            __wbg___wbindgen_is_string_cd444516edc5b180: function(arg0) {
                const ret = typeof(arg0) === 'string';
                return ret;
            },
            __wbg___wbindgen_is_undefined_9e4d92534c42d778: function(arg0) {
                const ret = arg0 === undefined;
                return ret;
            },
            __wbg___wbindgen_throw_be289d5034ed271b: function(arg0, arg1) {
                throw new Error(getStringFromWasm0(arg0, arg1));
            },
            __wbg__wbg_cb_unref_d9b87ff7982e3b21: function(arg0) {
                arg0._wbg_cb_unref();
            },
            __wbg_call_389efe28435a9388: function() { return handleError(function (arg0, arg1) {
                const ret = arg0.call(arg1);
                return ret;
            }, arguments); },
            __wbg_call_4708e0c13bdc8e95: function() { return handleError(function (arg0, arg1, arg2) {
                const ret = arg0.call(arg1, arg2);
                return ret;
            }, arguments); },
            __wbg_close_0d7e4d5ee8b35de4: function(arg0) {
                arg0.close();
            },
            __wbg_create_23ba2c76bff8a4bd: function(arg0) {
                const ret = Object.create(arg0);
                return ret;
            },
            __wbg_crypto_86f2631e91b51511: function(arg0) {
                const ret = arg0.crypto;
                return ret;
            },
            __wbg_data_5330da50312d0bc1: function(arg0) {
                const ret = arg0.data;
                return ret;
            },
            __wbg_debug_46a93995fc6f8820: function(arg0, arg1, arg2, arg3) {
                console.debug(arg0, arg1, arg2, arg3);
            },
            __wbg_debug_a4099fa12db6cd61: function(arg0) {
                console.debug(arg0);
            },
            __wbg_error_794d0ffc9d00d5c3: function(arg0, arg1, arg2, arg3) {
                console.error(arg0, arg1, arg2, arg3);
            },
            __wbg_error_9a7fe3f932034cde: function(arg0) {
                console.error(arg0);
            },
            __wbg_getRandomValues_b3f15fcbfabb0f8b: function() { return handleError(function (arg0, arg1) {
                arg0.getRandomValues(arg1);
            }, arguments); },
            __wbg_getTime_1e3cd1391c5c3995: function(arg0) {
                const ret = arg0.getTime();
                return ret;
            },
            __wbg_info_148d043840582012: function(arg0) {
                console.info(arg0);
            },
            __wbg_info_9e602cf10c5c690b: function(arg0, arg1, arg2, arg3) {
                console.info(arg0, arg1, arg2, arg3);
            },
            __wbg_length_32ed9a279acd054c: function(arg0) {
                const ret = arg0.length;
                return ret;
            },
            __wbg_mark_05056c522bddc362: function() { return handleError(function (arg0, arg1, arg2) {
                arg0.mark(getStringFromWasm0(arg1, arg2));
            }, arguments); },
            __wbg_mark_24a1a597f4f00679: function() { return handleError(function (arg0, arg1, arg2, arg3) {
                arg0.mark(getStringFromWasm0(arg1, arg2), arg3);
            }, arguments); },
            __wbg_measure_0b7379f5cfacac6d: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4, arg5, arg6) {
                arg0.measure(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4), getStringFromWasm0(arg5, arg6));
            }, arguments); },
            __wbg_measure_7728846525e2cced: function() { return handleError(function (arg0, arg1, arg2, arg3) {
                arg0.measure(getStringFromWasm0(arg1, arg2), arg3);
            }, arguments); },
            __wbg_msCrypto_d562bbe83e0d4b91: function(arg0) {
                const ret = arg0.msCrypto;
                return ret;
            },
            __wbg_new_0_73afc35eb544e539: function() {
                const ret = new Date();
                return ret;
            },
            __wbg_new_from_slice_a3d2629dc1826784: function(arg0, arg1) {
                const ret = new Uint8Array(getArrayU8FromWasm0(arg0, arg1));
                return ret;
            },
            __wbg_new_no_args_1c7c842f08d00ebb: function(arg0, arg1) {
                const ret = new Function(getStringFromWasm0(arg0, arg1));
                return ret;
            },
            __wbg_new_with_length_a2c39cbe88fd8ff1: function(arg0) {
                const ret = new Uint8Array(arg0 >>> 0);
                return ret;
            },
            __wbg_node_e1f24f89a7336c2e: function(arg0) {
                const ret = arg0.node;
                return ret;
            },
            __wbg_performance_121b9855d716e029: function() {
                const ret = globalThis.performance;
                return ret;
            },
            __wbg_postMessage_2041f4e90af61318: function() { return handleError(function (arg0, arg1) {
                arg0.postMessage(arg1);
            }, arguments); },
            __wbg_process_3975fd6c72f520aa: function(arg0) {
                const ret = arg0.process;
                return ret;
            },
            __wbg_prototypesetcall_bdcdcc5842e4d77d: function(arg0, arg1, arg2) {
                Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
            },
            __wbg_queueMicrotask_0aa0a927f78f5d98: function(arg0) {
                const ret = arg0.queueMicrotask;
                return ret;
            },
            __wbg_queueMicrotask_5bb536982f78a56f: function(arg0) {
                queueMicrotask(arg0);
            },
            __wbg_randomFillSync_f8c153b79f285817: function() { return handleError(function (arg0, arg1) {
                arg0.randomFillSync(arg1);
            }, arguments); },
            __wbg_require_b74f47fc2d022fd6: function() { return handleError(function () {
                const ret = module.require;
                return ret;
            }, arguments); },
            __wbg_resolve_002c4b7d9d8f6b64: function(arg0) {
                const ret = Promise.resolve(arg0);
                return ret;
            },
            __wbg_set_6cb8631f80447a67: function() { return handleError(function (arg0, arg1, arg2) {
                const ret = Reflect.set(arg0, arg1, arg2);
                return ret;
            }, arguments); },
            __wbg_set_onmessage_ea7cc2ba099021cd: function(arg0, arg1) {
                arg0.onmessage = arg1;
            },
            __wbg_static_accessor_GLOBAL_12837167ad935116: function() {
                const ret = typeof global === 'undefined' ? null : global;
                return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
            },
            __wbg_static_accessor_GLOBAL_THIS_e628e89ab3b1c95f: function() {
                const ret = typeof globalThis === 'undefined' ? null : globalThis;
                return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
            },
            __wbg_static_accessor_SELF_a621d3dfbb60d0ce: function() {
                const ret = typeof self === 'undefined' ? null : self;
                return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
            },
            __wbg_static_accessor_WINDOW_f8727f0cf888e0bd: function() {
                const ret = typeof window === 'undefined' ? null : window;
                return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
            },
            __wbg_subarray_a96e1fef17ed23cb: function(arg0, arg1, arg2) {
                const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
                return ret;
            },
            __wbg_then_b9e7b3b5f1a9e1b5: function(arg0, arg1) {
                const ret = arg0.then(arg1);
                return ret;
            },
            __wbg_versions_4e31226f5e8dc909: function(arg0) {
                const ret = arg0.versions;
                return ret;
            },
            __wbg_warn_a40b971467b219c7: function(arg0, arg1, arg2, arg3) {
                console.warn(arg0, arg1, arg2, arg3);
            },
            __wbg_warn_f7ae1b2e66ccb930: function(arg0) {
                console.warn(arg0);
            },
            __wbindgen_cast_0000000000000001: function(arg0, arg1) {
                // Cast intrinsic for `Closure(Closure { dtor_idx: 57, function: Function { arguments: [Externref], shim_idx: 322, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
                const ret = makeMutClosure(arg0, arg1, wasm.wasm_bindgen__closure__destroy__h55b17bab907bc820, wasm_bindgen__convert__closures_____invoke__hda77bde18f178b9a);
                return ret;
            },
            __wbindgen_cast_0000000000000002: function(arg0, arg1) {
                // Cast intrinsic for `Closure(Closure { dtor_idx: 57, function: Function { arguments: [NamedExternref("MessageEvent")], shim_idx: 58, ret: Unit, inner_ret: Some(Unit) }, mutable: false }) -> Externref`.
                const ret = makeClosure(arg0, arg1, wasm.wasm_bindgen__closure__destroy__h55b17bab907bc820, wasm_bindgen__convert__closures_____invoke__ha05f777c292bb18e);
                return ret;
            },
            __wbindgen_cast_0000000000000003: function(arg0, arg1) {
                // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
                const ret = getArrayU8FromWasm0(arg0, arg1);
                return ret;
            },
            __wbindgen_cast_0000000000000004: function(arg0, arg1) {
                // Cast intrinsic for `Ref(String) -> Externref`.
                const ret = getStringFromWasm0(arg0, arg1);
                return ret;
            },
            __wbindgen_init_externref_table: function() {
                const table = wasm.__wbindgen_externrefs;
                const offset = table.grow(4);
                table.set(0, undefined);
                table.set(offset + 0, undefined);
                table.set(offset + 1, null);
                table.set(offset + 2, true);
                table.set(offset + 3, false);
            },
        };
        return {
            __proto__: null,
            "./worker_bg.js": import0,
        };
    }

    function wasm_bindgen__convert__closures_____invoke__hda77bde18f178b9a(arg0, arg1, arg2) {
        wasm.wasm_bindgen__convert__closures_____invoke__hda77bde18f178b9a(arg0, arg1, arg2);
    }

    function wasm_bindgen__convert__closures_____invoke__ha05f777c292bb18e(arg0, arg1, arg2) {
        wasm.wasm_bindgen__convert__closures_____invoke__ha05f777c292bb18e(arg0, arg1, arg2);
    }

    function addToExternrefTable0(obj) {
        const idx = wasm.__externref_table_alloc();
        wasm.__wbindgen_externrefs.set(idx, obj);
        return idx;
    }

    const CLOSURE_DTORS = (typeof FinalizationRegistry === 'undefined')
        ? { register: () => {}, unregister: () => {} }
        : new FinalizationRegistry(state => state.dtor(state.a, state.b));

    function debugString(val) {
        // primitive types
        const type = typeof val;
        if (type == 'number' || type == 'boolean' || val == null) {
            return  `${val}`;
        }
        if (type == 'string') {
            return `"${val}"`;
        }
        if (type == 'symbol') {
            const description = val.description;
            if (description == null) {
                return 'Symbol';
            } else {
                return `Symbol(${description})`;
            }
        }
        if (type == 'function') {
            const name = val.name;
            if (typeof name == 'string' && name.length > 0) {
                return `Function(${name})`;
            } else {
                return 'Function';
            }
        }
        // objects
        if (Array.isArray(val)) {
            const length = val.length;
            let debug = '[';
            if (length > 0) {
                debug += debugString(val[0]);
            }
            for(let i = 1; i < length; i++) {
                debug += ', ' + debugString(val[i]);
            }
            debug += ']';
            return debug;
        }
        // Test for built-in
        const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
        let className;
        if (builtInMatches && builtInMatches.length > 1) {
            className = builtInMatches[1];
        } else {
            // Failed to match the standard '[object ClassName]'
            return toString.call(val);
        }
        if (className == 'Object') {
            // we're a user defined class or Object
            // JSON.stringify avoids problems with cycles, and is generally much
            // easier than looping through ownProperties of `val`.
            try {
                return 'Object(' + JSON.stringify(val) + ')';
            } catch (_) {
                return 'Object';
            }
        }
        // errors
        if (val instanceof Error) {
            return `${val.name}: ${val.message}\n${val.stack}`;
        }
        // TODO we could test for more things here, like `Set`s and `Map`s.
        return className;
    }

    function getArrayU8FromWasm0(ptr, len) {
        ptr = ptr >>> 0;
        return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
    }

    let cachedDataViewMemory0 = null;
    function getDataViewMemory0() {
        if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
            cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
        }
        return cachedDataViewMemory0;
    }

    function getStringFromWasm0(ptr, len) {
        ptr = ptr >>> 0;
        return decodeText(ptr, len);
    }

    let cachedUint8ArrayMemory0 = null;
    function getUint8ArrayMemory0() {
        if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
            cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
        }
        return cachedUint8ArrayMemory0;
    }

    function handleError(f, args) {
        try {
            return f.apply(this, args);
        } catch (e) {
            const idx = addToExternrefTable0(e);
            wasm.__wbindgen_exn_store(idx);
        }
    }

    function isLikeNone(x) {
        return x === undefined || x === null;
    }

    function makeClosure(arg0, arg1, dtor, f) {
        const state = { a: arg0, b: arg1, cnt: 1, dtor };
        const real = (...args) => {

            // First up with a closure we increment the internal reference
            // count. This ensures that the Rust closure environment won't
            // be deallocated while we're invoking it.
            state.cnt++;
            try {
                return f(state.a, state.b, ...args);
            } finally {
                real._wbg_cb_unref();
            }
        };
        real._wbg_cb_unref = () => {
            if (--state.cnt === 0) {
                state.dtor(state.a, state.b);
                state.a = 0;
                CLOSURE_DTORS.unregister(state);
            }
        };
        CLOSURE_DTORS.register(real, state, state);
        return real;
    }

    function makeMutClosure(arg0, arg1, dtor, f) {
        const state = { a: arg0, b: arg1, cnt: 1, dtor };
        const real = (...args) => {

            // First up with a closure we increment the internal reference
            // count. This ensures that the Rust closure environment won't
            // be deallocated while we're invoking it.
            state.cnt++;
            const a = state.a;
            state.a = 0;
            try {
                return f(a, state.b, ...args);
            } finally {
                state.a = a;
                real._wbg_cb_unref();
            }
        };
        real._wbg_cb_unref = () => {
            if (--state.cnt === 0) {
                state.dtor(state.a, state.b);
                state.a = 0;
                CLOSURE_DTORS.unregister(state);
            }
        };
        CLOSURE_DTORS.register(real, state, state);
        return real;
    }

    function passStringToWasm0(arg, malloc, realloc) {
        if (realloc === undefined) {
            const buf = cachedTextEncoder.encode(arg);
            const ptr = malloc(buf.length, 1) >>> 0;
            getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
            WASM_VECTOR_LEN = buf.length;
            return ptr;
        }

        let len = arg.length;
        let ptr = malloc(len, 1) >>> 0;

        const mem = getUint8ArrayMemory0();

        let offset = 0;

        for (; offset < len; offset++) {
            const code = arg.charCodeAt(offset);
            if (code > 0x7F) break;
            mem[ptr + offset] = code;
        }
        if (offset !== len) {
            if (offset !== 0) {
                arg = arg.slice(offset);
            }
            ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
            const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
            const ret = cachedTextEncoder.encodeInto(arg, view);

            offset += ret.written;
            ptr = realloc(ptr, len, offset, 1) >>> 0;
        }

        WASM_VECTOR_LEN = offset;
        return ptr;
    }

    let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
    cachedTextDecoder.decode();
    function decodeText(ptr, len) {
        return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
    }

    const cachedTextEncoder = new TextEncoder();

    if (!('encodeInto' in cachedTextEncoder)) {
        cachedTextEncoder.encodeInto = function (arg, view) {
            const buf = cachedTextEncoder.encode(arg);
            view.set(buf);
            return {
                read: arg.length,
                written: buf.length
            };
        };
    }

    let WASM_VECTOR_LEN = 0;

    let wasmModule, wasm;
    function __wbg_finalize_init(instance, module) {
        wasm = instance.exports;
        wasmModule = module;
        cachedDataViewMemory0 = null;
        cachedUint8ArrayMemory0 = null;
        wasm.__wbindgen_start();
        return wasm;
    }

    async function __wbg_load(module, imports) {
        if (typeof Response === 'function' && module instanceof Response) {
            if (typeof WebAssembly.instantiateStreaming === 'function') {
                try {
                    return await WebAssembly.instantiateStreaming(module, imports);
                } catch (e) {
                    const validResponse = module.ok && expectedResponseType(module.type);

                    if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                        console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                    } else { throw e; }
                }
            }

            const bytes = await module.arrayBuffer();
            return await WebAssembly.instantiate(bytes, imports);
        } else {
            const instance = await WebAssembly.instantiate(module, imports);

            if (instance instanceof WebAssembly.Instance) {
                return { instance, module };
            } else {
                return instance;
            }
        }

        function expectedResponseType(type) {
            switch (type) {
                case 'basic': case 'cors': case 'default': return true;
            }
            return false;
        }
    }

    function initSync(module) {
        if (wasm !== undefined) return wasm;


        if (module !== undefined) {
            if (Object.getPrototypeOf(module) === Object.prototype) {
                ({module} = module)
            } else {
                console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
            }
        }

        const imports = __wbg_get_imports();
        if (!(module instanceof WebAssembly.Module)) {
            module = new WebAssembly.Module(module);
        }
        const instance = new WebAssembly.Instance(module, imports);
        return __wbg_finalize_init(instance, module);
    }

    async function __wbg_init(module_or_path) {
        if (wasm !== undefined) return wasm;


        if (module_or_path !== undefined) {
            if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
                ({module_or_path} = module_or_path)
            } else {
                console.warn('using deprecated parameters for the initialization function; pass a single object instead')
            }
        }

        if (module_or_path === undefined && script_src !== undefined) {
            module_or_path = script_src.replace(/\.js$/, "_bg.wasm");
        }
        const imports = __wbg_get_imports();

        if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
            module_or_path = fetch(module_or_path);
        }

        const { instance, module } = await __wbg_load(await module_or_path, imports);

        return __wbg_finalize_init(instance, module);
    }

    return Object.assign(__wbg_init, { initSync }, exports);
})({ __proto__: null });
