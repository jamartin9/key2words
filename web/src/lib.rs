pub mod agent;

use base64ct::{Base64, Encoding};
use bip39::Mnemonic;
use gloo::console;
use gloo::utils::document;
use wasm_bindgen::JsCast;
use web_sys::HtmlElement;
use ybc::TileCtx::{Ancestor, Child, Parent};
use yew::platform::spawn_local;
use yew::prelude::*;
use yew_agent::oneshot::{use_oneshot_runner, OneshotProvider};

use crate::agent::{ConvertTask, WorkerInput, WorkerOutput};

#[function_component]
pub fn Main() -> Html {
    // MAYBE add date/time picker for key duration
    let converted = use_state(|| "".to_string()); // state for converted key output (rerender)
    let outproc = use_state(|| false); // state for conversion process status (rerender)
    let rows = use_state(|| 1_u32); // state for number of rows in textarea (rerender)
    let infmt = use_state(|| "MNEMONIC".to_string()); // state for format of text area (rerender for new generation)
    let input = use_mut_ref(|| "".to_string()); // state for input text area
    let outfmt = use_mut_ref(|| "PGP".to_string()); // state for format of output text
    let pass = use_mut_ref(|| "".to_string()); // state for password
    let save = use_mut_ref(|| false); // state for password
    let convert_task = use_oneshot_runner::<ConvertTask>();
    let onclick = {
        let input = input.clone();
        let convert_task = convert_task.clone();
        let infmt = infmt.clone();
        let outfmt = outfmt.clone();
        let pass = pass.clone();
        let outproc = outproc.clone();
        let rows = rows.clone();
        let converted = converted.clone(); // update output
        let save = save.clone(); // save output
        Callback::from(move |_| {
            let input = input.clone();
            let convert_task = convert_task.clone();
            let infmt = infmt.clone();
            let outfmt = outfmt.clone();
            let pass = pass.clone();
            let outproc = outproc.clone();
            let rows = rows.clone();
            let converted = converted.clone(); // update output
            let save = save.clone(); // save output

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
            outproc.set(true);
            // start the worker
            spawn_local(async move {
                let rows = rows.clone();
                let converted = converted.clone(); // update output
                let save = save.clone(); // save output

                let output_value: WorkerOutput = convert_task
                    .run(WorkerInput {
                        contents: input.borrow_mut().to_string(),
                        pass: pass.borrow_mut().to_string(),
                        infmt: fmt,
                        outfmt: outfmt.borrow_mut().to_string(),
                    })
                    .await;
                // worker is done so set size/contents of key and change is-loading class
                rows.set(
                    output_value
                        .converted
                        .lines()
                        .count()
                        .try_into()
                        .unwrap_or(1),
                );
                outproc.set(false);
                converted.set(output_value.converted.clone());
                console::log!("got response from worker");
                if (*save).clone().into_inner() {
                    let link = document()
                        .create_element("a")
                        .unwrap()
                        .dyn_into::<HtmlElement>()
                        .unwrap();
                    link.set_attribute("id", "downloadlink").unwrap();
                    let (download_name, encoded) = match output_value.fmt.as_str() {
                        "TOR" => (
                            String::from("hs_ed25519_secret_key"),
                            Base64::encode_string(&output_value.bin.unwrap()),
                        ), // use binary for tor key
                        "SSH" => (
                            String::from("id_ed25519"),
                            Base64::encode_string(output_value.converted.as_bytes()),
                        ),
                        "PGP" => (
                            String::from("key.gpg"),
                            Base64::encode_string(output_value.converted.as_bytes()),
                        ),
                        "MNEMONIC" => (
                            String::from("words.txt"),
                            Base64::encode_string(output_value.converted.as_bytes()),
                        ),
                        _ => (
                            String::from("unknown.txt"),
                            Base64::encode_string("".as_bytes()),
                        ),
                    };
                    link.set_attribute("download", download_name.as_str())
                        .unwrap();
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
            })
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
        <style>{"html { overflow-y: auto; }"}</style>
        <ybc::Hero
            body_classes={classes!("has-background-black")}
            size={ybc::HeroSize::Fullheight}
            head_classes={classes!("has-background-dark")}
            head={html!{
                <ybc::Navbar
                    navstart={html!{}}
                    navend={html!{<ybc::NavbarItem>
                                    <ybc::Title classes={classes!("has-text-white")} size={ybc::HeaderSize::Is4}>{"PGP | SSH | TOR words"}</ybc::Title>
                                    </ybc::NavbarItem>}}
                    //navburger=false
                    navmenu_classes={classes!("has-background-dark")}
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
                                        <ybc::Button onclick={&onclick}>{"Convert"}</ybc::Button>
                                    </ybc::Control>
                                    <ybc::Control>
                                        <ybc::Checkbox name={String::from("save")} update={savecb} checked={(*save).clone().into_inner()} classes={classes!("has-text-white")}>{"Save"}</ybc::Checkbox>
                                    </ybc::Control>
                                </ybc::Field>
                                <ybc::Field>
                                    <ybc::TextArea
                                        name={String::from("KeyOutput")}
                                        value={(*converted).clone()}
                                        update={donecb}
                                        size={ybc::Size::Large} rows={*rows}
                                        control_size={ybc::Size::Large} loading={(*outproc).clone()}
                                        placeholder={String::from("Output Generated Here...")}
                                        readonly={true} fixed_size={false}>
                                    </ybc::TextArea>
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

#[function_component]
pub fn App() -> Html {
    html! {
        <OneshotProvider<ConvertTask> path="/key2words/worker.js">
            <Main />
        </OneshotProvider<ConvertTask>>
    }
}
