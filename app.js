let O=0,V=`string`,T=1,W=`Object`,L=`utf-8`,_=80,N=null,K=`undefined`,X=4,U=`function`,R=128,Q=Array,M=Error,Z=Object,P=Uint8Array,Y=globalThis,S=undefined;var E=(async(a,b)=>{if(typeof Response===U&&a instanceof Response){if(typeof WebAssembly.instantiateStreaming===U){try{return await WebAssembly.instantiateStreaming(a,b)}catch(b){if(a.headers.get(`Content-Type`)!=`application/wasm`){console.warn(`\`WebAssembly.instantiateStreaming\` failed because your server does not serve wasm with \`application/wasm\` MIME type. Falling back to \`WebAssembly.instantiate\` which is slower. Original error:\\n`,b)}else{throw b}}};const c=await a.arrayBuffer();return await WebAssembly.instantiate(c,b)}else{const c=await WebAssembly.instantiate(a,b);if(c instanceof WebAssembly.Instance){return {instance:c,module:a}}else{return c}}});var s=(a=>{const b=typeof a;if(b==`number`||b==`boolean`||a==N){return `${a}`};if(b==V){return `"${a}"`};if(b==`symbol`){const b=a.description;if(b==N){return `Symbol`}else{return `Symbol(${b})`}};if(b==U){const b=a.name;if(typeof b==V&&b.length>O){return `Function(${b})`}else{return `Function`}};if(Q.isArray(a)){const b=a.length;let c=`[`;if(b>O){c+=s(a[O])};for(let d=T;d<b;d++){c+=`, `+ s(a[d])};c+=`]`;return c};const c=/\[object ([^\]]+)\]/.exec(toString.call(a));let d;if(c.length>T){d=c[T]}else{return toString.call(a)};if(d==W){try{return `Object(`+ JSON.stringify(a)+ `)`}catch(a){return W}};if(a instanceof M){return `${a.name}: ${a.message}\n${a.stack}`};return d});var u=((b,c,d)=>{a.wasm_bindgen__convert__closures__invoke1__h2981a160eaec7ce1(b,c,h(d))});var G=((a,b)=>{});var z=((b,c,d)=>{try{a.wasm_bindgen__convert__closures__invoke1_ref__hddd5d2ab81720365(b,c,y(d))}finally{f[x++]=S}});var D=((a,b)=>{a=a>>>O;const c=C();const d=c.subarray(a/X,a/X+ b);const e=[];for(let a=O;a<d.length;a++){e.push(k(d[a]))};return e});var k=(a=>{const b=i(a);j(a);return b});var h=(a=>{if(g===f.length)f.push(f.length+ T);const b=g;g=f[b];f[b]=a;return b});function A(b,c){try{return b.apply(this,c)}catch(b){a.__wbindgen_exn_store(h(b))}}var J=(async(b)=>{if(a!==S)return a;if(typeof b===K){b=new URL(`app_bg.wasm`,import.meta.url)};const c=F();if(typeof b===V||typeof Request===U&&b instanceof Request||typeof URL===U&&b instanceof URL){b=fetch(b)};G(c);const {instance:d,module:e}=await E(await b,c);return H(d,e)});var I=(b=>{if(a!==S)return a;const c=F();G(c);if(!(b instanceof WebAssembly.Module)){b=new WebAssembly.Module(b)};const d=new WebAssembly.Instance(b,c);return H(d,b)});var r=(()=>{if(q===N||q.byteLength===O){q=new Int32Array(a.memory.buffer)};return q});var p=(a=>a===S||a===N);var i=(a=>f[a]);var H=((b,d)=>{a=b.exports;J.__wbindgen_wasm_module=d;q=N;B=N;c=N;a.__wbindgen_start();return a});var F=(()=>{const b={};b.wbg={};b.wbg.__wbindgen_string_new=((a,b)=>{const c=e(a,b);return h(c)});b.wbg.__wbg_warn_f260f49434e45e62=(a=>{console.warn(i(a))});b.wbg.__wbindgen_object_drop_ref=(a=>{k(a)});b.wbg.__wbg_performance_72f95fe5952939b5=(()=>{const a=Y.performance;return h(a)});b.wbg.__wbindgen_is_undefined=(a=>{const b=i(a)===S;return b});b.wbg.__wbg_create_7d555f9fb99eb703=(a=>{const b=Z.create(i(a));return h(b)});b.wbg.__wbg_set_759f75cd92b612d2=function(){return A(((a,b,c)=>{const d=Reflect.set(i(a),i(b),i(c));return d}),arguments)};b.wbg.__wbg_measure_7ca0e5cfef892340=function(){return A(((a,b,c,d)=>{i(a).measure(e(b,c),i(d))}),arguments)};b.wbg.__wbg_mark_6045ef1772587264=function(){return A(((a,b,c)=>{i(a).mark(e(b,c))}),arguments)};b.wbg.__wbg_measure_1d846b814d43d7e1=function(){return A(((a,b,c,d,f,g,h)=>{i(a).measure(e(b,c),e(d,f),e(g,h))}),arguments)};b.wbg.__wbg_body_64abc9aba1891e91=(a=>{const b=i(a).body;return p(b)?O:h(b)});b.wbg.__wbg_lastChild_a62e3fbaab87f734=(a=>{const b=i(a).lastChild;return p(b)?O:h(b)});b.wbg.__wbg_removeChild_942eb9c02243d84d=function(){return A(((a,b)=>{const c=i(a).removeChild(i(b));return h(c)}),arguments)};b.wbg.__wbg_new_abda76e883ba8a5f=(()=>{const a=new M();return h(a)});b.wbg.__wbg_stack_658279fe44541cf6=((b,c)=>{const d=i(c).stack;const e=o(d,a.__wbindgen_malloc,a.__wbindgen_realloc);const f=l;r()[b/X+ T]=f;r()[b/X+ O]=e});b.wbg.__wbg_error_f851667af71bcfc6=((b,c)=>{let d;let f;try{d=b;f=c;console.error(e(b,c))}finally{a.__wbindgen_free(d,f,T)}});b.wbg.__wbg_instanceof_Window_3e5cd1f48c152d01=(a=>{let b;try{b=i(a) instanceof Window}catch(a){b=!1}const c=b;return c});b.wbg.__wbg_document_d609202d16c38224=(a=>{const b=i(a).document;return p(b)?O:h(b)});b.wbg.__wbindgen_string_get=((b,c)=>{const d=i(c);const e=typeof d===V?d:S;var f=p(e)?O:o(e,a.__wbindgen_malloc,a.__wbindgen_realloc);var g=l;r()[b/X+ T]=g;r()[b/X+ O]=f});b.wbg.__wbg_self_f0e34d89f33b99fd=function(){return A((()=>{const a=self.self;return h(a)}),arguments)};b.wbg.__wbg_window_d3b084224f4774d7=function(){return A((()=>{const a=window.window;return h(a)}),arguments)};b.wbg.__wbg_globalThis_9caa27ff917c6860=function(){return A((()=>{const a=Y.globalThis;return h(a)}),arguments)};b.wbg.__wbg_global_35dfdd59a4da3e74=function(){return A((()=>{const a=global.global;return h(a)}),arguments)};b.wbg.__wbg_newnoargs_c62ea9419c21fbac=((a,b)=>{const c=new Function(e(a,b));return h(c)});b.wbg.__wbg_call_90c26b09837aba1c=function(){return A(((a,b)=>{const c=i(a).call(i(b));return h(c)}),arguments)};b.wbg.__wbindgen_object_clone_ref=(a=>{const b=i(a);return h(b)});b.wbg.__wbindgen_debug_string=((b,c)=>{const d=s(i(c));const e=o(d,a.__wbindgen_malloc,a.__wbindgen_realloc);const f=l;r()[b/X+ T]=f;r()[b/X+ O]=e});b.wbg.__wbg_call_5da1969d7cd31ccd=function(){return A(((a,b,c)=>{const d=i(a).call(i(b),i(c));return h(d)}),arguments)};b.wbg.__wbg_is_ff7acd231c75c0e4=((a,b)=>{const c=Z.is(i(a),i(b));return c});b.wbg.__wbg_createElement_fdd5c113cb84539e=function(){return A(((a,b,c)=>{const d=i(a).createElement(e(b,c));return h(d)}),arguments)};b.wbg.__wbg_instanceof_HtmlElement_55a0f0f0f0f0118e=(a=>{let b;try{b=i(a) instanceof HTMLElement}catch(a){b=!1}const c=b;return c});b.wbg.__wbg_setAttribute_e7b72a5e7cfcb5a3=function(){return A(((a,b,c,d,f)=>{i(a).setAttribute(e(b,c),e(d,f))}),arguments)};b.wbg.__wbg_click_0bd1396258764b36=(a=>{i(a).click()});b.wbg.__wbg_getElementById_65b9547a428b5eb4=((a,b,c)=>{const d=i(a).getElementById(e(b,c));return p(d)?O:h(d)});b.wbg.__wbg_remove_0d26d36fd4f25c4e=(a=>{i(a).remove()});b.wbg.__wbg_location_176c34e89c2c9d80=(a=>{const b=i(a).location;return h(b)});b.wbg.__wbg_href_160af2ae1328d7b7=function(){return A(((b,c)=>{const d=i(c).href;const e=o(d,a.__wbindgen_malloc,a.__wbindgen_realloc);const f=l;r()[b/X+ T]=f;r()[b/X+ O]=e}),arguments)};b.wbg.__wbg_newwithbase_f4989aa5bbd5cc29=function(){return A(((a,b,c,d)=>{const f=new URL(e(a,b),e(c,d));return h(f)}),arguments)};b.wbg.__wbg_toString_6577cc00288ad588=(a=>{const b=i(a).toString();return h(b)});b.wbg.__wbg_replace_0236079f661987ca=((a,b,c,d,f)=>{const g=i(a).replace(e(b,c),e(d,f));return h(g)});b.wbg.__wbg_new_ffc6d4d085022169=(()=>{const a=new Q();return h(a)});b.wbg.__wbg_push_901f3914205d44de=((a,b)=>{const c=i(a).push(i(b));return c});b.wbg.__wbg_new_9fb8d994e1c0aaac=(()=>{const a=new Z();return h(a)});b.wbg.__wbg_newwithstrsequenceandoptions_4806b667a908f161=function(){return A(((a,b)=>{const c=new Blob(i(a),i(b));return h(c)}),arguments)};b.wbg.__wbg_createObjectURL_9fbd9480174d7f02=function(){return A(((b,c)=>{const d=URL.createObjectURL(i(c));const e=o(d,a.__wbindgen_malloc,a.__wbindgen_realloc);const f=l;r()[b/X+ T]=f;r()[b/X+ O]=e}),arguments)};b.wbg.__wbg_new_ff19bad2f50bf62b=function(){return A(((a,b)=>{const c=new Worker(e(a,b));return h(c)}),arguments)};b.wbg.__wbg_setonmessage_9961dd0a8670d682=((a,b)=>{i(a).onmessage=i(b)});b.wbg.__wbindgen_memory=(()=>{const b=a.memory;return h(b)});b.wbg.__wbg_buffer_a448f833075b71ba=(a=>{const b=i(a).buffer;return h(b)});b.wbg.__wbg_newwithbyteoffsetandlength_d0482f893617af71=((a,b,c)=>{const d=new P(i(a),b>>>O,c>>>O);return h(d)});b.wbg.__wbg_new_8f67e318f15d7254=(a=>{const b=new P(i(a));return h(b)});b.wbg.__wbg_postMessage_f071c51d77b68152=function(){return A(((a,b)=>{i(a).postMessage(i(b))}),arguments)};b.wbg.__wbg_data_ba3ea616b5392abf=(a=>{const b=i(a).data;return h(b)});b.wbg.__wbg_length_1d25fa9e4ac21ce7=(a=>{const b=i(a).length;return b});b.wbg.__wbg_set_2357bf09366ee480=((a,b,c)=>{i(a).set(i(b),c>>>O)});b.wbg.__wbg_crypto_58f13aa23ffcb166=(a=>{const b=i(a).crypto;return h(b)});b.wbg.__wbindgen_is_object=(a=>{const b=i(a);const c=typeof b===`object`&&b!==N;return c});b.wbg.__wbg_process_5b786e71d465a513=(a=>{const b=i(a).process;return h(b)});b.wbg.__wbg_versions_c2ab80650590b6a2=(a=>{const b=i(a).versions;return h(b)});b.wbg.__wbg_node_523d7bd03ef69fba=(a=>{const b=i(a).node;return h(b)});b.wbg.__wbindgen_is_string=(a=>{const b=typeof i(a)===V;return b});b.wbg.__wbg_msCrypto_abcb1295e768d1f2=(a=>{const b=i(a).msCrypto;return h(b)});b.wbg.__wbg_newwithlength_6c2df9e2f3028c43=(a=>{const b=new P(a>>>O);return h(b)});b.wbg.__wbg_require_2784e593a4674877=function(){return A((()=>{const a=module.require;return h(a)}),arguments)};b.wbg.__wbindgen_is_function=(a=>{const b=typeof i(a)===U;return b});b.wbg.__wbg_randomFillSync_a0d98aa11c81fe89=function(){return A(((a,b)=>{i(a).randomFillSync(k(b))}),arguments)};b.wbg.__wbg_subarray_2e940e41c0f5a1d9=((a,b,c)=>{const d=i(a).subarray(b>>>O,c>>>O);return h(d)});b.wbg.__wbg_getRandomValues_504510b5564925af=function(){return A(((a,b)=>{i(a).getRandomValues(i(b))}),arguments)};b.wbg.__wbg_mark_bad820680b8580c2=function(){return A(((a,b,c,d)=>{i(a).mark(e(b,c),i(d))}),arguments)};b.wbg.__wbg_debug_34c9290896ec9856=(a=>{console.debug(i(a))});b.wbg.__wbg_info_d7d58472d0bab115=(a=>{console.info(i(a))});b.wbg.__wbg_error_e60eff06f24ab7a4=(a=>{console.error(i(a))});b.wbg.__wbg_debug_678fc976919895d2=((a,b,c,d)=>{console.debug(i(a),i(b),i(c),i(d))});b.wbg.__wbg_info_7904cb81904ea2ec=((a,b,c,d)=>{console.info(i(a),i(b),i(c),i(d))});b.wbg.__wbg_warn_0345511f899411e2=((a,b,c,d)=>{console.warn(i(a),i(b),i(c),i(d))});b.wbg.__wbg_error_ce00188b70015ed4=((a,b,c,d)=>{console.error(i(a),i(b),i(c),i(d))});b.wbg.__wbindgen_throw=((a,b)=>{throw new M(e(a,b))});b.wbg.__wbg_queueMicrotask_adae4bc085237231=(a=>{const b=i(a).queueMicrotask;return h(b)});b.wbg.__wbg_resolve_6e1c6553a82f85b7=(a=>{const b=Promise.resolve(i(a));return h(b)});b.wbg.__wbindgen_cb_drop=(a=>{const b=k(a).original;if(b.cnt--==T){b.a=O;return !0};const c=!1;return c});b.wbg.__wbg_then_3ab08cd4fbb91ae9=((a,b)=>{const c=i(a).then(i(b));return h(c)});b.wbg.__wbg_queueMicrotask_4d890031a6a5a50c=(a=>{queueMicrotask(i(a))});b.wbg.__wbg_target_52ddf6955f636bf5=(a=>{const b=i(a).target;return p(b)?O:h(b)});b.wbg.__wbg_instanceof_HtmlInputElement_e7869aaef9cbb0e6=(a=>{let b;try{b=i(a) instanceof HTMLInputElement}catch(a){b=!1}const c=b;return c});b.wbg.__wbg_value_e024243a9dae20bc=((b,c)=>{const d=i(c).value;const e=o(d,a.__wbindgen_malloc,a.__wbindgen_realloc);const f=l;r()[b/X+ T]=f;r()[b/X+ O]=e});b.wbg.__wbg_instanceof_HtmlSelectElement_2d43d9e14dd8e866=(a=>{let b;try{b=i(a) instanceof HTMLSelectElement}catch(a){b=!1}const c=b;return c});b.wbg.__wbg_value_30ed7fed7e3a14ba=((b,c)=>{const d=i(c).value;const e=o(d,a.__wbindgen_malloc,a.__wbindgen_realloc);const f=l;r()[b/X+ T]=f;r()[b/X+ O]=e});b.wbg.__wbg_instanceof_HtmlTextAreaElement_ce81e455dc21bc93=(a=>{let b;try{b=i(a) instanceof HTMLTextAreaElement}catch(a){b=!1}const c=b;return c});b.wbg.__wbg_value_57e57170f6952449=((b,c)=>{const d=i(c).value;const e=o(d,a.__wbindgen_malloc,a.__wbindgen_realloc);const f=l;r()[b/X+ T]=f;r()[b/X+ O]=e});b.wbg.__wbg_nextSibling_bafccd3347d24543=(a=>{const b=i(a).nextSibling;return p(b)?O:h(b)});b.wbg.__wbg_insertBefore_726c1640c419e940=function(){return A(((a,b,c)=>{const d=i(a).insertBefore(i(b),i(c));return h(d)}),arguments)};b.wbg.__wbg_error_a526fb08a0205972=((b,c)=>{var d=D(b,c).slice();a.__wbindgen_free(b,c*X,X);console.error(...d)});b.wbg.__wbg_setnodeValue_630c6470d05b600e=((a,b,c)=>{i(a).nodeValue=b===O?S:e(b,c)});b.wbg.__wbg_namespaceURI_7cc7ef157e398356=((b,c)=>{const d=i(c).namespaceURI;var e=p(d)?O:o(d,a.__wbindgen_malloc,a.__wbindgen_realloc);var f=l;r()[b/X+ T]=f;r()[b/X+ O]=e});b.wbg.__wbg_createElementNS_524b05a6070757b6=function(){return A(((a,b,c,d,f)=>{const g=i(a).createElementNS(b===O?S:e(b,c),e(d,f));return h(g)}),arguments)};b.wbg.__wbg_cloneNode_405d5ea3f7e0098a=function(){return A((a=>{const b=i(a).cloneNode();return h(b)}),arguments)};b.wbg.__wbg_setchecked_c1d5c3726082e274=((a,b)=>{i(a).checked=b!==O});b.wbg.__wbg_setvalue_5b3442ff620b4a5d=((a,b,c)=>{i(a).value=e(b,c)});b.wbg.__wbg_setvalue_a11f3069fd7a1805=((a,b,c)=>{i(a).value=e(b,c)});b.wbg.__wbg_createTextNode_7ff0c034b2855f66=((a,b,c)=>{const d=i(a).createTextNode(e(b,c));return h(d)});b.wbg.__wbg_setinnerHTML_ce0d6527ce4086f2=((a,b,c)=>{i(a).innerHTML=e(b,c)});b.wbg.__wbg_childNodes_a5762b4b3e073cf6=(a=>{const b=i(a).childNodes;return h(b)});b.wbg.__wbg_from_71add2e723d1f1b2=(a=>{const b=Q.from(i(a));return h(b)});b.wbg.__wbg_length_1009b1af0c481d7b=(a=>{const b=i(a).length;return b});b.wbg.__wbg_get_f01601b5a68d10e3=((a,b)=>{const c=i(a)[b>>>O];return h(c)});b.wbg.__wbg_setsubtreeid_e1fab6b578c800cf=((a,b)=>{i(a).__yew_subtree_id=b>>>O});b.wbg.__wbg_addEventListener_374cbfd2bbc19ccf=function(){return A(((a,b,c,d,f)=>{i(a).addEventListener(e(b,c),i(d),i(f))}),arguments)};b.wbg.__wbg_composedPath_12a068e57a98cf90=(a=>{const b=i(a).composedPath();return h(b)});b.wbg.__wbg_cachekey_b81c1aacc6a0645c=((a,b)=>{const c=i(b).__yew_subtree_cache_key;r()[a/X+ T]=p(c)?O:c;r()[a/X+ O]=!p(c)});b.wbg.__wbg_subtreeid_e80a1798fee782f9=((a,b)=>{const c=i(b).__yew_subtree_id;r()[a/X+ T]=p(c)?O:c;r()[a/X+ O]=!p(c)});b.wbg.__wbg_instanceof_Element_3f326a19cc457941=(a=>{let b;try{b=i(a) instanceof Element}catch(a){b=!1}const c=b;return c});b.wbg.__wbg_bubbles_f1cdd0584446cad0=(a=>{const b=i(a).bubbles;return b});b.wbg.__wbg_parentElement_72e144c2e8d9e0b5=(a=>{const b=i(a).parentElement;return p(b)?O:h(b)});b.wbg.__wbg_parentNode_92a7017b3a4fad43=(a=>{const b=i(a).parentNode;return p(b)?O:h(b)});b.wbg.__wbg_instanceof_ShadowRoot_0bd39e89ab117f86=(a=>{let b;try{b=i(a) instanceof ShadowRoot}catch(a){b=!1}const c=b;return c});b.wbg.__wbg_host_09eee5e3d9cf59a1=(a=>{const b=i(a).host;return h(b)});b.wbg.__wbg_setcachekey_75bcd45312087529=((a,b)=>{i(a).__yew_subtree_cache_key=b>>>O});b.wbg.__wbg_cancelBubble_976cfdf7ac449a6c=(a=>{const b=i(a).cancelBubble;return b});b.wbg.__wbg_listenerid_6dcf1c62b7b7de58=((a,b)=>{const c=i(b).__yew_listener_id;r()[a/X+ T]=p(c)?O:c;r()[a/X+ O]=!p(c)});b.wbg.__wbg_setlistenerid_f2e783343fa0cec1=((a,b)=>{i(a).__yew_listener_id=b>>>O});b.wbg.__wbg_removeAttribute_2e200daefb9f3ed4=function(){return A(((a,b,c)=>{i(a).removeAttribute(e(b,c))}),arguments)};b.wbg.__wbg_textContent_2f37235e13f8484b=((b,c)=>{const d=i(c).textContent;var e=p(d)?O:o(d,a.__wbindgen_malloc,a.__wbindgen_realloc);var f=l;r()[b/X+ T]=f;r()[b/X+ O]=e});b.wbg.__wbg_outerHTML_b5a8d952b5615778=((b,c)=>{const d=i(c).outerHTML;const e=o(d,a.__wbindgen_malloc,a.__wbindgen_realloc);const f=l;r()[b/X+ T]=f;r()[b/X+ O]=e});b.wbg.__wbindgen_closure_wrapper1402=((a,b,c)=>{const d=t(a,b,_,u);return h(d)});b.wbg.__wbindgen_closure_wrapper1679=((a,b,c)=>{const d=v(a,b,_,w);return h(d)});b.wbg.__wbindgen_closure_wrapper2471=((a,b,c)=>{const d=t(a,b,_,z);return h(d)});return b});var C=(()=>{if(B===N||B.byteLength===O){B=new Uint32Array(a.memory.buffer)};return B});var w=((b,c,d)=>{a.wasm_bindgen__convert__closures__invoke1_mut__h440aa6b5c6763e3e(b,c,h(d))});var t=((b,c,d,e)=>{const f={a:b,b:c,cnt:T,dtor:d};const g=(...b)=>{f.cnt++;try{return e(f.a,f.b,...b)}finally{if(--f.cnt===O){a.__wbindgen_export_2.get(f.dtor)(f.a,f.b);f.a=O}}};g.original=f;return g});var j=(a=>{if(a<132)return;f[a]=g;g=a});var v=((b,c,d,e)=>{const f={a:b,b:c,cnt:T,dtor:d};const g=(...b)=>{f.cnt++;const c=f.a;f.a=O;try{return e(c,f.b,...b)}finally{if(--f.cnt===O){a.__wbindgen_export_2.get(f.dtor)(c,f.b)}else{f.a=c}}};g.original=f;return g});var o=((a,b,c)=>{if(c===S){const c=m.encode(a);const e=b(c.length,T)>>>O;d().subarray(e,e+ c.length).set(c);l=c.length;return e};let e=a.length;let f=b(e,T)>>>O;const g=d();let h=O;for(;h<e;h++){const b=a.charCodeAt(h);if(b>127)break;g[f+ h]=b};if(h!==e){if(h!==O){a=a.slice(h)};f=c(f,e,e=h+ a.length*3,T)>>>O;const b=d().subarray(f+ h,f+ e);const g=n(a,b);h+=g.written};l=h;return f});var d=(()=>{if(c===N||c.byteLength===O){c=new P(a.memory.buffer)};return c});var e=((a,c)=>{a=a>>>O;return b.decode(d().subarray(a,a+ c))});var y=(a=>{if(x==T)throw new M(`out of js stack`);f[--x]=a;return x});let a;const b=typeof TextDecoder!==K?new TextDecoder(L,{ignoreBOM:!0,fatal:!0}):{decode:()=>{throw M(`TextDecoder not available`)}};if(typeof TextDecoder!==K){b.decode()};let c=N;const f=new Q(R).fill(S);f.push(S,N,!0,!1);let g=f.length;let l=O;const m=typeof TextEncoder!==K?new TextEncoder(L):{encode:()=>{throw M(`TextEncoder not available`)}};const n=typeof m.encodeInto===U?((a,b)=>m.encodeInto(a,b)):((a,b)=>{const c=m.encode(a);b.set(c);return {read:a.length,written:c.length}});let q=N;let x=R;let B=N;export default J;export{I as initSync}