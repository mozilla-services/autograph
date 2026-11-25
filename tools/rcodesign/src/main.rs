pub mod errors;

use crate::errors::SignError;
use actix_multipart::form::{MultipartForm, tempfile::TempFile, text::Text};
use actix_web::{App, HttpResponse, HttpServer, Responder, get, post};
use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

#[get("/")]
async fn root() -> impl Responder {
  HttpResponse::Ok().body("howdy")
}

#[derive(MultipartForm)]
struct Payload {
  #[multipart(limit = "1250MB")]
  file: TempFile,
  pem: TempFile,
  sig_flag: Option<Text<String>>,
}

#[post("/")]
async fn sign(MultipartForm(form): MultipartForm<Payload>) -> Result<HttpResponse, SignError> {
  /*
  * signing a mach-o executable
  * rcodesign sign \
    --pem-file pem-encoded-key-and-cert.pem \
    --code-signature-flags runtime \
    path/to/executable
  *
  * signing a pkg, dmg, or app bundle
  * rcodesign sign \
    --pem-file pem-encoded-key-and-cert.pem \
    path/to/installer.pkg
  */

  // base command
  let mut cmd = Command::new("./rcodesign-cli");

  // performing a signing operation
  cmd.arg("sign");

  // adding pem encoded key and cert file
  cmd.arg("--pem-file").arg(form.pem.file.path());

  // if a signature flag is provided, add it
  if let Some(sig_flag) = form.sig_flag {
    cmd
      .arg("--code-signature-flags")
      .arg(sig_flag.to_string());
  }

  // add file to sign
  cmd.arg(form.file.file.path());

  // add the signed file path
  let signed = NamedTempFile::new()?;
  cmd.arg(signed.path());

  let output = cmd.output()?;

  if output.status.success() {
    let file_bytes = std::fs::read(signed.path())?;
    Ok(HttpResponse::Ok().body(file_bytes))
  } else {
    // write output so we can debug
    std::io::stdout().write_all(&output.stdout)?;
    std::io::stderr().write_all(&output.stderr)?;
    Ok(HttpResponse::InternalServerError().body("failed"))
  }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
  HttpServer::new(|| App::new().service(root).service(sign))
    .bind(("0.0.0.0", 8000))?
    .run()
    .await
}
