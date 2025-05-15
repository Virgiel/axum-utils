use axum::{
    body::Body,
    http::StatusCode,
    response::{IntoResponse, Response},
};

pub type HttpResult = Result<Response, HttpError>;

pub struct HttpError {
    pub status: StatusCode,
    body: Body,
}

impl HttpError {
    pub fn new(status: StatusCode, body: Body) -> Self {
        Self { status, body }
    }

    pub fn status(status: StatusCode) -> Self {
        Self::new(status, Body::empty())
    }

    pub fn response(self) -> Response<Body> {
        Response::builder()
            .status(self.status)
            .body(self.body)
            .unwrap()
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        self.response()
    }
}

impl From<StatusCode> for HttpError {
    fn from(status: StatusCode) -> Self {
        Self::status(status)
    }
}

impl<E: std::error::Error> From<(StatusCode, E)> for HttpError {
    fn from((code, err): (StatusCode, E)) -> Self {
        eprintln!("{}", err);
        Self::new(code, Body::empty())
    }
}

pub trait ErrorHelper<O>: Sized {
    fn unexpected(self) -> O {
        self.status(StatusCode::INTERNAL_SERVER_ERROR)
    }
    fn bad_request(self) -> O {
        self.status(StatusCode::BAD_REQUEST)
    }
    fn bad_gateway(self) -> O {
        self.status(StatusCode::BAD_GATEWAY)
    }
    fn status(self, status: StatusCode) -> O;
}

impl<T, E: std::error::Error> ErrorHelper<Result<T, HttpError>> for Result<T, E> {
    fn status(self, status: StatusCode) -> Result<T, HttpError> {
        self.map_err(|e| (status, e).into())
    }
}

impl<T> ErrorHelper<Result<T, HttpError>> for Option<T> {
    fn status(self, status: StatusCode) -> Result<T, HttpError> {
        self.ok_or_else(|| status.into())
    }
}

impl<E: std::error::Error> ErrorHelper<HttpError> for E {
    fn status(self, status: StatusCode) -> HttpError {
        (status, self).into()
    }
}
