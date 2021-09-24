use chrono::{DateTime, FixedOffset};

pub type TimeStamp = DateTime<FixedOffset>;

/// An enum of arbitrary values so we can give extra information to some entities in this crate
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum Properties {
    Bool(bool),
    I32(i32),
    I64(i64),
    //F64(f64),
    Str(String),
    DateTime(TimeStamp),
}
