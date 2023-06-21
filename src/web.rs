use gloo::console;
use ybc::TileCtx::{Ancestor, Child, Parent};
use yew::prelude::*;
use yew_agent::{use_bridge, UseBridgeHandle};

use crate::agent::{MyWorker, WorkerInput, WorkerOutput};

#[function_component(App)]
pub fn app() -> Html {
    let converted = use_state(|| "".to_string()); // state for converted key output (rerender)
    let outproc = use_state(|| "is-large".to_string()); // state for conversion process status (rerender)
    let rows = use_state(|| 1 as u32); // state for number of rows in textarea (rerender)
    let input = use_mut_ref(|| "".to_string()); // state for input text area
    let infmt = use_mut_ref(|| "".to_string()); // state for format of text area
    let outfmt = use_mut_ref(|| "".to_string()); // state for format of output text
    let pass = use_mut_ref(|| "".to_string()); // state for password
    let bridge = {
        let converted = converted.clone(); // update output
        let outproc = outproc.clone(); // update loading class of textfield
        let rows = rows.clone(); // update output size
        let bridge: UseBridgeHandle<MyWorker> = use_bridge(move |response| match response {
            WorkerOutput { converted: val } => {
                // worker is done so set size/contents of key and change is-loading class
                rows.set(val.lines().count().try_into().unwrap_or_else(|_| 1));
                outproc.set("is-large".to_string());
                converted.set(val);
                console::log!("got response from worker");
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
            // send message to bridged worker with mut ref fields to avoid blocking ui thread
            bridge.send(WorkerInput {
                contents: input.borrow_mut().to_string(),
                pass: pass.borrow_mut().to_string(),
                infmt: infmt.borrow_mut().to_string(),
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
        Callback::from(move |field: String| {
            *outfmt.borrow_mut() = field;
        })
    };
    let incb = {
        Callback::from(move |field: String| {
            *infmt.borrow_mut() = field;
        })
    };
    let passcb = {
        let pass = pass.clone();
        Callback::from(move |field: String| {
            *pass.borrow_mut() = field;
        })
    };
    let donecb = { Callback::from(move |_field: String| {}) };
    let onsubmit = { Callback::from(move |_: _| {}) };

    html! {
        <>
        <ybc::Navbar
            classes={classes!("is-success")}
            padded=true
            navbrand={html!{
                <ybc::NavbarItem>
                    <ybc::Title classes={classes!("has-text-white")} size={ybc::HeaderSize::Is4}>{"PGP | SSH | TOR words"}</ybc::Title>
                </ybc::NavbarItem>
            }}
            navstart={html!{}}
            navend={html!{
                <>
                <ybc::NavbarItem>
                    <ybc::ButtonAnchor classes={classes!("is-black", "is-outlined")} rel={String::from("noopener noreferrer")} target={String::from("_blank")} href="https://github.com/jamartin9/key2words">
                        {"Source"}
                    </ybc::ButtonAnchor>
                </ybc::NavbarItem>
                </>
            }}
        />
        <ybc::Hero
            classes={classes!("is-light")}
            size={ybc::HeroSize::FullheightWithNavbar}
            body={html!{
                <ybc::Container classes={classes!("is-centered")}>
                    <ybc::Tile ctx={Ancestor} classes={classes!("is-vertical")}>
                    <ybc::Tile ctx={Parent} size={ybc::TileSize::Twelve}>
                        <ybc::Tile ctx={Parent}>
                            <ybc::Tile ctx={Child} classes={classes!("notification", "is-success")}>
                            <ybc::Subtitle size={ybc::HeaderSize::Is3} classes={classes!("has-text-white")}>{ "Key Form" }</ybc::Subtitle>
                    <form onsubmit={onsubmit}>
                                <ybc::Field>
                                    <ybc::Control>
                                     <p> {"Input Format"} </p>
                                     <ybc::Select name={String::from("input")} value={String::from("MNEMONIC")} update={incb} >
                                           <option>{"PGP"}</option>
                                           <option>{"SSH"}</option>
                                           <option selected=true>{"MNEMONIC"}</option>
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
                                     <ybc::Select name={String::from("ouput")} value={String::from("PGP")} update={outcb} >
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
                                </ybc::Field>
                                <ybc::Field>
                                    <ybc::Control classes={classes!((*outproc).clone())}>
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
                            </form>
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
