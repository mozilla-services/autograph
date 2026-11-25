use actix_web::HttpResponse;
use serde_derive::Serialize;
use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SignError {
  message: String,
}

impl SignError {
  pub fn new<M: Into<String>>(message: M) -> Self {
    let message = message.into();
    Self { message }
  }

  pub fn from_source<S: fmt::Display, E: fmt::Display>(source: S, err: E) -> Self {
    Self {
      message: format!("{source}: {err}"),
    }
  }
}

// Use default implementation of Error
impl std::error::Error for SignError {}

impl fmt::Display for SignError {
  fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
    write!(formatter, "{self:?}")?;
    Ok(())
  }
}

impl actix_web::error::ResponseError for SignError {
  fn error_response(&self) -> HttpResponse {
    HttpResponse::InternalServerError().json(self)
  }
}

macro_rules! impl_from_error {
  ($error: ty) => {
    impl From<$error> for SignError {
      fn from(error: $error) -> Self {
        Self::from_source(stringify!($error), error)
      }
    }
  };
}

impl_from_error!(actix_web::http::header::ToStrError);
impl_from_error!(std::io::Error);
