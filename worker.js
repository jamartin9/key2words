let wasm_bindgen;(()=>{let K=0,O=`string`,N=1,Q=`Object`,I=`utf-8`,G=null,F=`undefined`,T=4,U=25,P=`function`,M=Array,J=Error,S=Object,L=Uint8Array,R=globalThis,H=undefined;var z=(async(a,b)=>{if(typeof Response===P&&a instanceof Response){if(typeof WebAssembly.instantiateStreaming===P){try{return await WebAssembly.instantiateStreaming(a,b)}catch(b){if(a.headers.get(`Content-Type`)!=`application/wasm`){console.warn(`\`WebAssembly.instantiateStreaming\` failed because your server does not serve wasm with \`application/wasm\` MIME type. Falling back to \`WebAssembly.instantiate\` which is slower. Original error:\\n`,b)}else{throw b}}};const c=await a.arrayBuffer();return await WebAssembly.instantiate(c,b)}else{const c=await WebAssembly.instantiate(a,b);if(c instanceof WebAssembly.Instance){return {instance:c,module:a}}else{return c}}});var n=(a=>{const b=typeof a;if(b==`number`||b==`boolean`||a==G){return `${a}`};if(b==O){return `"${a}"`};if(b==`symbol`){const b=a.description;if(b==G){return `Symbol`}else{return `Symbol(${b})`}};if(b==P){const b=a.name;if(typeof b==O&&b.length>K){return `Function(${b})`}else{return `Function`}};if(M.isArray(a)){const b=a.length;let c=`[`;if(b>K){c+=n(a[K])};for(let d=N;d<b;d++){c+=`, `+ n(a[d])};c+=`]`;return c};const c=/\[object ([^\]]+)\]/.exec(toString.call(a));let d;if(c.length>N){d=c[N]}else{return toString.call(a)};if(d==Q){try{return `Object(`+ JSON.stringify(a)+ `)`}catch(a){return Q}};if(a instanceof J){return `${a.name}: ${a.message}\n${a.stack}`};return d});var v=((a,b,d)=>{c.wasm_bindgen__convert__closures__invoke1__hb606a59da997b5ae(a,b,j(d))});var B=((a,b)=>{});var m=(a=>{const b=k(a);l(a);return b});var j=(a=>{if(i===h.length)h.push(h.length+ N);const b=i;i=h[b];h[b]=a;return b});function y(a,b){try{return a.apply(this,b)}catch(a){c.__wbindgen_exn_store(j(a))}}var t=(()=>{if(s===G||s.byteLength===K){s=new Int32Array(c.memory.buffer)};return s});var k=(a=>h[a]);var E=(async(a)=>{if(c!==H)return c;if(typeof a===F&&b!==F){a=b.replace(/\.js$/,`_bg.wasm`)};const d=A();if(typeof a===O||typeof Request===P&&a instanceof Request||typeof URL===P&&a instanceof URL){a=fetch(a)};B(d);const {instance:e,module:f}=await z(await a,d);return C(e,f)});var D=(a=>{if(c!==H)return c;const b=A();B(b);if(!(a instanceof WebAssembly.Module)){a=new WebAssembly.Module(a)};const d=new WebAssembly.Instance(a,b);return C(d,a)});var A=(()=>{const a={};a.wbg={};a.wbg.__wbindgen_string_new=((a,b)=>{const c=g(a,b);return j(c)});a.wbg.__wbg_warn_f260f49434e45e62=(a=>{console.warn(k(a))});a.wbg.__wbindgen_object_drop_ref=(a=>{m(a)});a.wbg.__wbg_performance_72f95fe5952939b5=(()=>{const a=R.performance;return j(a)});a.wbg.__wbindgen_is_undefined=(a=>{const b=k(a)===H;return b});a.wbg.__wbg_create_7d555f9fb99eb703=(a=>{const b=S.create(k(a));return j(b)});a.wbg.__wbg_set_759f75cd92b612d2=function(){return y(((a,b,c)=>{const d=Reflect.set(k(a),k(b),k(c));return d}),arguments)};a.wbg.__wbg_measure_7ca0e5cfef892340=function(){return y(((a,b,c,d)=>{k(a).measure(g(b,c),k(d))}),arguments)};a.wbg.__wbg_mark_6045ef1772587264=function(){return y(((a,b,c)=>{k(a).mark(g(b,c))}),arguments)};a.wbg.__wbg_measure_1d846b814d43d7e1=function(){return y(((a,b,c,d,e,f,h)=>{k(a).measure(g(b,c),g(d,e),g(f,h))}),arguments)};a.wbg.__wbg_close_3d3019a22dda6227=(a=>{k(a).close()});a.wbg.__wbindgen_memory=(()=>{const a=c.memory;return j(a)});a.wbg.__wbg_buffer_a448f833075b71ba=(a=>{const b=k(a).buffer;return j(b)});a.wbg.__wbg_newwithbyteoffsetandlength_d0482f893617af71=((a,b,c)=>{const d=new L(k(a),b>>>K,c>>>K);return j(d)});a.wbg.__wbg_new_8f67e318f15d7254=(a=>{const b=new L(k(a));return j(b)});a.wbg.__wbg_postMessage_101f1eec24e6c59b=function(){return y(((a,b)=>{k(a).postMessage(k(b))}),arguments)};a.wbg.__wbg_data_ba3ea616b5392abf=(a=>{const b=k(a).data;return j(b)});a.wbg.__wbg_length_1d25fa9e4ac21ce7=(a=>{const b=k(a).length;return b});a.wbg.__wbg_set_2357bf09366ee480=((a,b,c)=>{k(a).set(k(b),c>>>K)});a.wbg.__wbg_setonmessage_a7281508ee498972=((a,b)=>{k(a).onmessage=k(b)});a.wbg.__wbg_new0_622c21a64f3d83ea=(()=>{const a=new Date();return j(a)});a.wbg.__wbg_getTime_9272be78826033e1=(a=>{const b=k(a).getTime();return b});a.wbg.__wbg_crypto_58f13aa23ffcb166=(a=>{const b=k(a).crypto;return j(b)});a.wbg.__wbindgen_is_object=(a=>{const b=k(a);const c=typeof b===`object`&&b!==G;return c});a.wbg.__wbg_process_5b786e71d465a513=(a=>{const b=k(a).process;return j(b)});a.wbg.__wbg_versions_c2ab80650590b6a2=(a=>{const b=k(a).versions;return j(b)});a.wbg.__wbg_node_523d7bd03ef69fba=(a=>{const b=k(a).node;return j(b)});a.wbg.__wbindgen_is_string=(a=>{const b=typeof k(a)===O;return b});a.wbg.__wbg_msCrypto_abcb1295e768d1f2=(a=>{const b=k(a).msCrypto;return j(b)});a.wbg.__wbg_newwithlength_6c2df9e2f3028c43=(a=>{const b=new L(a>>>K);return j(b)});a.wbg.__wbg_require_2784e593a4674877=function(){return y((()=>{const a=module.require;return j(a)}),arguments)};a.wbg.__wbindgen_is_function=(a=>{const b=typeof k(a)===P;return b});a.wbg.__wbg_randomFillSync_a0d98aa11c81fe89=function(){return y(((a,b)=>{k(a).randomFillSync(m(b))}),arguments)};a.wbg.__wbg_subarray_2e940e41c0f5a1d9=((a,b,c)=>{const d=k(a).subarray(b>>>K,c>>>K);return j(d)});a.wbg.__wbg_getRandomValues_504510b5564925af=function(){return y(((a,b)=>{k(a).getRandomValues(k(b))}),arguments)};a.wbg.__wbg_self_f0e34d89f33b99fd=function(){return y((()=>{const a=self.self;return j(a)}),arguments)};a.wbg.__wbg_window_d3b084224f4774d7=function(){return y((()=>{const a=window.window;return j(a)}),arguments)};a.wbg.__wbg_globalThis_9caa27ff917c6860=function(){return y((()=>{const a=R.globalThis;return j(a)}),arguments)};a.wbg.__wbg_global_35dfdd59a4da3e74=function(){return y((()=>{const a=global.global;return j(a)}),arguments)};a.wbg.__wbg_newnoargs_c62ea9419c21fbac=((a,b)=>{const c=new Function(g(a,b));return j(c)});a.wbg.__wbg_call_90c26b09837aba1c=function(){return y(((a,b)=>{const c=k(a).call(k(b));return j(c)}),arguments)};a.wbg.__wbindgen_object_clone_ref=(a=>{const b=k(a);return j(b)});a.wbg.__wbg_call_5da1969d7cd31ccd=function(){return y(((a,b,c)=>{const d=k(a).call(k(b),k(c));return j(d)}),arguments)};a.wbg.__wbg_mark_bad820680b8580c2=function(){return y(((a,b,c,d)=>{k(a).mark(g(b,c),k(d))}),arguments)};a.wbg.__wbg_debug_34c9290896ec9856=(a=>{console.debug(k(a))});a.wbg.__wbg_info_d7d58472d0bab115=(a=>{console.info(k(a))});a.wbg.__wbg_error_e60eff06f24ab7a4=(a=>{console.error(k(a))});a.wbg.__wbg_debug_678fc976919895d2=((a,b,c,d)=>{console.debug(k(a),k(b),k(c),k(d))});a.wbg.__wbg_info_7904cb81904ea2ec=((a,b,c,d)=>{console.info(k(a),k(b),k(c),k(d))});a.wbg.__wbg_warn_0345511f899411e2=((a,b,c,d)=>{console.warn(k(a),k(b),k(c),k(d))});a.wbg.__wbg_error_ce00188b70015ed4=((a,b,c,d)=>{console.error(k(a),k(b),k(c),k(d))});a.wbg.__wbindgen_debug_string=((a,b)=>{const d=n(k(b));const e=r(d,c.__wbindgen_malloc,c.__wbindgen_realloc);const f=o;t()[a/T+ N]=f;t()[a/T+ K]=e});a.wbg.__wbindgen_throw=((a,b)=>{throw new J(g(a,b))});a.wbg.__wbg_queueMicrotask_adae4bc085237231=(a=>{const b=k(a).queueMicrotask;return j(b)});a.wbg.__wbg_resolve_6e1c6553a82f85b7=(a=>{const b=Promise.resolve(k(a));return j(b)});a.wbg.__wbindgen_cb_drop=(a=>{const b=m(a).original;if(b.cnt--==N){b.a=K;return !0};const c=!1;return c});a.wbg.__wbg_then_3ab08cd4fbb91ae9=((a,b)=>{const c=k(a).then(k(b));return j(c)});a.wbg.__wbg_queueMicrotask_4d890031a6a5a50c=(a=>{queueMicrotask(k(a))});a.wbg.__wbindgen_closure_wrapper161=((a,b,c)=>{const d=u(a,b,U,v);return j(d)});a.wbg.__wbindgen_closure_wrapper3288=((a,b,c)=>{const d=w(a,b,U,x);return j(d)});return a});var x=((a,b,d)=>{c.wasm_bindgen__convert__closures__invoke1_mut__h440aa6b5c6763e3e(a,b,j(d))});var u=((a,b,d,e)=>{const f={a:a,b:b,cnt:N,dtor:d};const g=(...a)=>{f.cnt++;try{return e(f.a,f.b,...a)}finally{if(--f.cnt===K){c.__wbindgen_export_2.get(f.dtor)(f.a,f.b);f.a=K}}};g.original=f;return g});var l=(a=>{if(a<132)return;h[a]=i;i=a});var w=((a,b,d,e)=>{const f={a:a,b:b,cnt:N,dtor:d};const g=(...a)=>{f.cnt++;const b=f.a;f.a=K;try{return e(b,f.b,...a)}finally{if(--f.cnt===K){c.__wbindgen_export_2.get(f.dtor)(b,f.b)}else{f.a=b}}};g.original=f;return g});var r=((a,b,c)=>{if(c===H){const c=p.encode(a);const d=b(c.length,N)>>>K;f().subarray(d,d+ c.length).set(c);o=c.length;return d};let d=a.length;let e=b(d,N)>>>K;const g=f();let h=K;for(;h<d;h++){const b=a.charCodeAt(h);if(b>127)break;g[e+ h]=b};if(h!==d){if(h!==K){a=a.slice(h)};e=c(e,d,d=h+ a.length*3,N)>>>K;const b=f().subarray(e+ h,e+ d);const g=q(a,b);h+=g.written};o=h;return e});var f=(()=>{if(e===G||e.byteLength===K){e=new L(c.memory.buffer)};return e});var g=((a,b)=>{a=a>>>K;return d.decode(f().subarray(a,a+ b))});var C=((a,b)=>{c=a.exports;E.__wbindgen_wasm_module=b;s=G;e=G;c.__wbindgen_start();return c});const a={};let b;if(typeof document!==F&&document.currentScript!==G){b=new URL(document.currentScript.src,location.href).toString()};let c=H;const d=typeof TextDecoder!==F?new TextDecoder(I,{ignoreBOM:!0,fatal:!0}):{decode:()=>{throw J(`TextDecoder not available`)}};if(typeof TextDecoder!==F){d.decode()};let e=G;const h=new M(128).fill(H);h.push(H,G,!0,!1);let i=h.length;let o=K;const p=typeof TextEncoder!==F?new TextEncoder(I):{encode:()=>{throw J(`TextEncoder not available`)}};const q=typeof p.encodeInto===P?((a,b)=>p.encodeInto(a,b)):((a,b)=>{const c=p.encode(a);b.set(c);return {read:a.length,written:c.length}});let s=G;wasm_bindgen=S.assign(E,{initSync:D},a)})()