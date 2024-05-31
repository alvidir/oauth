macro_rules! on_error {
    ($from:ty as $to:ty, $msg:tt) => {
        |error: $from| -> $to {
            error!(error = error.to_string(), $msg,);
            error.into()
        }
    };
    ($to:ty, $msg:tt) => {
        |error| -> $to {
            error!(error = error.to_string(), $msg,);
            <$to>::from(error)
        }
    };
}

pub(crate) use on_error;
