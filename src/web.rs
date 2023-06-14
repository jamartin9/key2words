//use anyhow::Result;
use ybc::TileCtx::{Ancestor, Child, Parent};
use yew::prelude::*;
use gloo::console;

use crate::keys::{KeyConverter, Converter};
use bip39::Language;
use anyhow::{anyhow, Result};

#[function_component(App)]
pub fn app() -> Html {
    let converted = use_state(|| "".to_string()); // state for converted key output (rerender)
    let input = use_mut_ref(|| "".to_string()); // state for input text area
    let infmt = use_mut_ref(|| "".to_string()); // state for format of text area
    let outfmt = use_mut_ref(|| "".to_string()); // state for format of output text

    let onclick = { // convert infmt textarea field into the converted field text in outfmt
        let converted = converted.clone();
        let input = input.clone();
        let infmt = infmt.clone();
        let outfmt = outfmt.clone();
        Callback::from(move |_| {
            let word_list_lang = Language::English;
            let key_convert: Result<KeyConverter> = match infmt.borrow_mut().as_str() {
                "SSH" => KeyConverter::from_ssh(input.borrow_mut().to_string(), None, word_list_lang),
                "PGP" => KeyConverter::from_gpg(input.borrow_mut().to_string(), None, word_list_lang),
                "MNEMONIC" => KeyConverter::from_mnemonic(input.borrow_mut().to_string(), word_list_lang, None, None, None, None),
                _ => Err(anyhow!("could not create converter")),
            };
            let result : Result<String> = match key_convert {
                Err(err) => Err(err),
                Ok(converter) => {
                    console::log!("using converter");
                    match outfmt.borrow_mut().as_str() {
                        "SSH" => Ok(converter.to_ssh().expect("ssh").0.to_string()),
                        "PGP" => Ok(converter.to_pgp().expect("pgp")),
                        "TOR" => Ok(converter.to_tor_address().expect("tor")),
                        "MNEMONIC" => Ok(converter.to_words().expect("words").to_string()),
                        _ => Err(anyhow!("Failed to get output format")),
                    }
                },
            };
            match result {
                Ok(content) => converted.set(content),
                Err(err) => console::log!(err.to_string()),
            }
            /*if *infmt.borrow_mut() == "SSH" {
                console::log!("converting for ssh in");
            } else if *infmt.borrow_mut() == "PGP"{
                console::log!("converting for pgp in");
            } else if *infmt.borrow_mut() == "MNEMONIC" {
                console::log!("converting for mnemonic in")
            }
            if *outfmt.borrow_mut() == "SSH" {
                console::log!("converting for ssh out");
            } else if *outfmt.borrow_mut() == "PGP" {
                console::log!("converting for pgp out");
            } else if *outfmt.borrow_mut() == "TOR" {
                console::log!("converting for tor out");
            }else if *outfmt.borrow_mut() == "MNEMONIC" {
                console::log!("converting for mnemonic out");
            }*/
           // let res = String::from("CONVERTED");
            //converted.set(res + &input.borrow_mut());
        })};
    // set the state from fields
    // MAYBE use Messages to avoid String copying
    let ontext = {
        Callback::from(move |field: String| {
            *input.borrow_mut() = field;
        })};
    let outcb = {
        Callback::from(move |field: String| {
            *outfmt.borrow_mut() = field;
        })};
    let incb = {
        Callback::from(move |field: String| {
            *infmt.borrow_mut() = field;
        })};
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
                            <ybc::Subtitle size={ybc::HeaderSize::Is3} classes={classes!("has-text-white")}>{(*converted).clone()}</ybc::Subtitle>
                                <ybc::Field>
                                    <ybc::Control>
                                     <p> {"Input Format"} </p>
                    <ybc::Select name={String::from("input")} value={String::from("SSH")} update={incb} >
                                           <option>{"PGP"}</option>
                                           <option selected=true>{"SSH"}</option>
                                           <option>{"MNEMONIC"}</option>
                                       </ybc::Select>
                                    </ybc::Control>
                                </ybc::Field>
                                <ybc::Field>
                                    <ybc::Control>
                                        <ybc::TextArea
                                            name={String::from("KeyText")}
                                            value={String::from("")}
                                            update={ontext}
                                            placeholder={String::from("Paste Text Here")}
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
                    <ybc::Select name={String::from("ouput")} value={String::from("MNEMONIC")} update={outcb} >
                                           <option>{"PGP"}</option>
                                           <option>{"SSH"}</option>
                                           <option selected=true>{"MNEMONIC"}</option>
                                           <option>{"TOR"}</option>
                                       </ybc::Select>
                                    </ybc::Control>
                                </ybc::Field>
                                <ybc::Field>
                                    <ybc::Control>
                                        <ybc::Button onclick={onclick}>{"Convert"}</ybc::Button>
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

pub fn web() {
    yew::Renderer::<App>::new().render();
}
