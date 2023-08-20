pub mod agent;

use base64ct::{Base64, Encoding};
use bip39::Mnemonic;
use gloo::console;
use gloo::utils::document;
use stylist::yew::{styled_component, Global};
use wasm_bindgen::JsCast;
use web_sys::HtmlElement;
use ybc::TileCtx::{Ancestor, Child, Parent};
use yew::prelude::*;
use yew_agent::{use_bridge, UseBridgeHandle};

use crate::agent::{MyWorker, WorkerInput, WorkerOutput};

#[styled_component]
pub fn App() -> Html { // MAYBE add date/time picker for key duration
    let converted = use_state(|| "".to_string()); // state for converted key output (rerender)
    let outproc = use_state(|| "is-large".to_string()); // state for conversion process status (rerender)
    let rows = use_state(|| 1_u32); // state for number of rows in textarea (rerender)
    let infmt = use_state(|| "MNEMONIC".to_string()); // state for format of text area (rerender for new generation)
    let input = use_mut_ref(|| "".to_string()); // state for input text area
    let outfmt = use_mut_ref(|| "PGP".to_string()); // state for format of output text
    let pass = use_mut_ref(|| "".to_string()); // state for password
    let save = use_mut_ref(|| false); // state for password
    let bridge = {
        // BUG breaks SSR (update to yew agent to new gloo worker?)
        let converted = converted.clone(); // update output
        let outproc = outproc.clone(); // update loading class of textfield
        let rows = rows.clone(); // update output size
        let save = save.clone(); // save output
        let bridge: UseBridgeHandle<MyWorker> = use_bridge(move |response| {
            let WorkerOutput {
                converted: val,
                fmt: outfmt,
                bin: binary,
            } = response;
            {
                // worker is done so set size/contents of key and change is-loading class
                rows.set(val.lines().count().try_into().unwrap_or(1));
                outproc.set("is-large".to_string());
                converted.set(val.clone());
                console::log!("got response from worker");
                if (*save).clone().into_inner() {
                    let link = document()
                        .create_element("a")
                        .unwrap()
                        .dyn_into::<HtmlElement>()
                        .unwrap();
                    link.set_attribute("id", "downloadlink").unwrap();
                    let (download_name, encoded) = match outfmt.as_str() {
                        "TOR" => (
                            String::from("hs_ed25519_secret_key"),
                            Base64::encode_string(&binary.unwrap()),
                        ), // use binary for tor key
                        "SSH" => (
                            String::from("id_ed25519"),
                            Base64::encode_string(val.as_bytes()),
                        ),
                        "PGP" => (
                            String::from("key.gpg"),
                            Base64::encode_string(val.as_bytes()),
                        ),
                        "MNEMONIC" => (
                            String::from("words.txt"),
                            Base64::encode_string(val.as_bytes()),
                        ),
                        _ => (
                            String::from("unknown.txt"),
                            Base64::encode_string("".as_bytes()),
                        ),
                    };
                    link.set_attribute("download", download_name.as_str())
                        .unwrap();
                    //data:application/octet-stream;base64,BASE64-ENCODED-DATA
                    link.set_attribute(
                        "href",
                        format!("data:application/octet-stream;base64,{}", encoded).as_str(),
                    )
                    .unwrap();
                    link.click();
                    document()
                        .get_element_by_id("downloadlink")
                        .unwrap()
                        .remove();
                }
            }
        });
        bridge
    };
    let onclick = {
        let input = input.clone();
        let infmt = infmt.clone();
        let outfmt = outfmt.clone();
        let pass = pass.clone();
        let outproc = outproc.clone();
        Callback::from(move |_| {
            //send message to bridged worker to avoid blocking ui thread
            let fmt = if input.borrow_mut().is_empty() {
                console::log!("Creating New Mnemonic");
                let mnem = Mnemonic::generate(24).expect("Could not generate words"); // MAYBE background generate?
                *input.borrow_mut() = mnem.to_string();
                infmt.set("MNEMONIC".to_string()); // BUG doesn't rerender/update instantly
                "MNEMONIC".to_string()
            } else {
                infmt.to_string()
            };
            bridge.send(WorkerInput {
                contents: input.borrow_mut().to_string(),
                pass: pass.borrow_mut().to_string(),
                infmt: fmt,
                outfmt: outfmt.borrow_mut().to_string(),
            });
            outproc.set("is-large is-loading".to_string()); // add loading class to textarea
        })
    };
    // set the state from fields
    // MAYBE use Messages to avoid String copying?
    let ontext = {
        let input = input.clone();
        Callback::from(move |field: String| {
            *input.borrow_mut() = field;
        })
    };
    let outcb = {
        let outfmt = outfmt.clone();
        Callback::from(move |field: String| {
            *outfmt.borrow_mut() = field;
        })
    };
    let incb = {
        let infmt = infmt.clone();
        Callback::from(move |field: String| {
            infmt.set(field);
        })
    };
    let passcb = {
        let pass = pass.clone();
        Callback::from(move |field: String| {
            *pass.borrow_mut() = field;
        })
    };
    let savecb = {
        let save = save.clone();
        Callback::from(move |field: bool| {
            *save.borrow_mut() = field;
        })
    };
    let donecb = { Callback::from(move |_field: String| {}) };

    html! {
        <>
        <Global css={css!(
            r#"
                html { /* https://github.com/jgthms/bulma/issues/527 vertical scroll bar always shown despite closed bug -_- */
                    overflow-y: auto;
                }
            "#
        )} />
        <ybc::Hero
            body_classes={classes!("has-background-black")}
            size={ybc::HeroSize::Fullheight}
            head_classes={classes!("has-background-dark")}
            head={html!{
                <ybc::Navbar
                    navburger=false
                    navbrand={html!{ // BUG add way to set classes on navbar-menu
                        <ybc::NavbarItem>
                            <ybc::ButtonAnchor classes={classes!("is-light", "is-outlined")} rel={String::from("noopener noreferrer")} target={String::from("_blank")} href="https://github.com/jamartin9/key2words">
                                {"Source"}
                            </ybc::ButtonAnchor>
                        </ybc::NavbarItem>
                    }}
                />
            }}
            body={html!{
                <ybc::Container classes={classes!("is-centered")}>
                    <ybc::Tile ctx={Ancestor} classes={classes!("is-vertical")}>
                    <ybc::Tile ctx={Parent} size={ybc::TileSize::Twelve}>
                        <ybc::Tile ctx={Parent}>
                            <ybc::Tile ctx={Child} classes={classes!("notification", "is-dark")}>
                            <ybc::Subtitle size={ybc::HeaderSize::Is3} classes={classes!("has-text-white")}>{ "Key Form" }</ybc::Subtitle>
                                <ybc::Field>
                                    <ybc::Control>
                                     <p> {"Input Format"} </p>
                                     <ybc::Select name={String::from("input")} value={(*infmt).clone()} update={incb} >
                                           <option value="PGP" selected={(*infmt).clone() == "PGP"}>{"PGP"}</option>
                                           <option value="SSH" selected={(*infmt).clone() == "SSH"}>{"SSH"}</option>
                                           <option value="MNEMONIC" selected={(*infmt).clone() == "MNEMONIC"}>{"MNEMONIC"}</option>
                                       </ybc::Select>
                                    </ybc::Control>
                                </ybc::Field>
                                <ybc::Field>
                                    <ybc::Control>
                                        <ybc::TextArea
                                            name={String::from("KeyText")}
                                            value={(*input).clone().into_inner()}
                                            update={ontext}
                                            placeholder={String::from("Paste Key Input Here")}
                                            readonly={false} >
                                        </ybc::TextArea>
                                    </ybc::Control>
                                </ybc::Field>
                                <ybc::Field>
                                    <ybc::Control>
                                    </ybc::Control>
                                </ybc::Field>
                                <ybc::Field>
                                    <ybc::Control>
                                     <p> {"Output Format"} </p>
                                     <ybc::Select name={String::from("ouput")} value={(*outfmt).clone().into_inner()} update={outcb} >
                                           <option selected=true>{"PGP"}</option>
                                           <option>{"SSH"}</option>
                                           <option>{"MNEMONIC"}</option>
                                           <option>{"TOR"}</option>
                                       </ybc::Select>
                                    </ybc::Control>
                                </ybc::Field>
                                <ybc::Field>
                                    <ybc::Control>
                                        <ybc::Input r#type={ybc::InputType::Password} update={passcb} name={String::from("pass")} value={(*pass).clone().into_inner()} placeholder={String::from("Optional Password")}></ybc::Input>
                                    </ybc::Control>
                                </ybc::Field>
                                <ybc::Field>
                                    <ybc::Control>
                                        <ybc::Button onclick={onclick}>{"Convert"}</ybc::Button>
                                    </ybc::Control>
                                    <ybc::Control>
                                        <ybc::Checkbox name={String::from("save")} update={savecb} checked={(*save).clone().into_inner()} classes={classes!("has-text-white")}>{"Save"}</ybc::Checkbox>
                                    </ybc::Control>
                                </ybc::Field>
                                <ybc::Field>
                                    <ybc::Control classes={classes!((*outproc).clone())}> // BUG TextArea loading is controlled by the control not a textarea property/attribute
                                        <ybc::TextArea
                                            name={String::from("KeyOutput")}
                                            value={(*converted).clone()}
                                            update={donecb}
                                            size={ybc::Size::Large} rows={*rows}
                                            placeholder={String::from("Output Generated Here...")}
                                            readonly={true} fixed_size={false}>
                                        </ybc::TextArea>
                                    </ybc::Control>
                                </ybc::Field>
                            </ybc::Tile>
                        </ybc::Tile>
                    </ybc::Tile>
                </ybc::Tile>
                </ybc::Container>
            }}>
        </ybc::Hero>
        </>
    }
}
