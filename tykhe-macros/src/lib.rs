extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{quote, ToTokens};
use std::{collections::HashSet, ops::Not};
use syn::{
    ext::IdentExt,
    parse::{Parse, ParseStream},
    parse_macro_input, FnArg, Ident, ItemFn, Pat, PatIdent, PatType, Token, Type, TypePath,
};

/// Decorates a function to verify and extact information from its associated token argument.
#[proc_macro_attribute]
pub fn with_token(metadata: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(metadata as WithTokenArgs);
    let Some(token_kind) = args.token_kind else {
        return quote!(compile_error!("the `kind` argument has to be set");).into();
    };

    let ItemFn {
        attrs,
        vis,
        sig,
        block,
    } = parse_macro_input!(input as ItemFn);

    let stmts = &block.stmts;

    let resolve_user_id = args.no_user_id.not().then(|| {
        quote! {
           let user_id = UserID::from_str(claims.payload().subject()).map_err(on_error!(
               uuid::Error as Error,
               "parsing token subject into user id"
           ))?;
        }
    });

    TokenStream::from(quote! {
        #(#attrs)* #vis #sig {
            let claims = self.token_srv.claims(token).await?;
            if !matches!(claims.payload().kind(), TokenKind::#token_kind) {
                return Err(Error::WrongToken);
            }

            #resolve_user_id

            #(#stmts)*
        }
    })
}

/// Replicates a function adding a token argument in its signature.
#[proc_macro_attribute]
pub fn derive_with_token_fn(metadata: TokenStream, input: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(input as ItemFn);
    let input_metadata = metadata.clone();
    let args = parse_macro_input!(input_metadata as WithTokenArgs);

    let mut replica_fn = input_fn.clone();

    // add sufix to the funtion name
    let fn_name: String = vec![&replica_fn.sig.ident.to_string(), "_with_token"].concat();
    replica_fn.sig.ident = Ident::new(&fn_name, Span::call_site());

    // determines if the attached funtion has the self receiver
    let mut has_receiver = false;

    // remove skiped arguments
    replica_fn.sig.inputs = replica_fn
        .sig
        .inputs
        .into_iter()
        .filter(|arg| {
            let FnArg::Typed(typed_arg) = arg else {
                has_receiver = true;
                return true;
            };

            let Pat::Ident(arg_ident) = typed_arg.pat.as_ref() else {
                return true;
            };

            !args.skips.contains(&arg_ident.ident)
        })
        .collect();

    // insert token agument
    let token_arg = FnArg::Typed(PatType {
        attrs: Vec::new(),
        pat: Box::new(Pat::Ident(PatIdent {
            attrs: Vec::new(),
            by_ref: None,
            mutability: None,
            ident: Ident::new("token", Span::call_site()),
            subpat: None,
        })),
        colon_token: Default::default(),
        ty: Box::new(Type::Path(TypePath {
            qself: None,
            path: Ident::new("Token", Span::call_site()).into(),
        })),
    });

    replica_fn
        .sig
        .inputs
        .insert(if has_receiver { 1 } else { 0 }, token_arg);

    let replica_fn = with_token(metadata, replica_fn.into_token_stream().into());
    let replica_fn = parse_macro_input!(replica_fn as ItemFn);

    TokenStream::from(quote! {
        #input_fn

        #replica_fn
    })
}

#[derive(Default)]
struct WithTokenArgs {
    /// TokenKind with which the token has to match.
    token_kind: Option<Ident>,
    /// Skip user ID processing. No user_id variable will be available in scope.
    no_user_id: bool,
    /// Arguments to be skiped from the new signature.
    skips: HashSet<Ident>,
}

impl Parse for WithTokenArgs {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut args = Self::default();
        while !input.is_empty() {
            let lookahead = input.lookahead1();
            if lookahead.peek(kw::kind) {
                if args.token_kind.is_some() {
                    return Err(input.error("expected only a single `kind` argument"));
                }

                let TokenKind(token_kind) = input.parse()?;
                args.token_kind = Some(token_kind);
            } else if lookahead.peek(kw::no_user_id) {
                let _ = input.parse::<kw::no_user_id>()?;
                args.no_user_id = true;
            } else if lookahead.peek(kw::skip) {
                let Skips(skips) = input.parse()?;
                args.skips = skips;
            } else {
                // Parse the unrecognized token tree to advance the parse
                // stream, and throw it away so we can keep parsing. Otherwise
                // this would become an endless while loop.
                let _ = input.parse::<proc_macro2::TokenTree>();
            }
        }

        Ok(args)
    }
}

struct TokenKind(Ident);

impl Parse for TokenKind {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let _ = input.parse::<kw::kind>();
        let content;
        let _ = syn::parenthesized!(content in input);

        Ok(Self(content.parse()?))
    }
}

struct Skips(HashSet<Ident>);

impl Parse for Skips {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let _ = input.parse::<kw::skip>();
        let content;
        let _ = syn::parenthesized!(content in input);
        let names = content.parse_terminated(Ident::parse_any, Token![,])?;
        let mut skips = HashSet::new();
        for name in names {
            if skips.contains(&name) {
                return Err(syn::Error::new(
                    name.span(),
                    "tried to skip the same field twice",
                ));
            } else {
                skips.insert(name);
            }
        }
        Ok(Self(skips))
    }
}

mod kw {
    syn::custom_keyword!(kind);
    syn::custom_keyword!(no_user_id);
    syn::custom_keyword!(skip);
}
