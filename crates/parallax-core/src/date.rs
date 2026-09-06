//! A dependency-free civil date, used for peer expiry. Serialized as `"YYYY-MM-DD"`.

use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Date {
    pub year: i32,
    pub month: u8,
    pub day: u8,
}

impl Date {
    pub fn new(year: i32, month: u8, day: u8) -> crate::Result<Self> {
        let d = Date { year, month, day };
        if !(1..=12).contains(&month) || day == 0 || day > d.days_in_month() {
            return Err(crate::Error::Malformed {
                what: "date",
                detail: format!("{year:04}-{month:02}-{day:02} is not a calendar date"),
            });
        }
        Ok(d)
    }

    fn days_in_month(&self) -> u8 {
        match self.month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            _ => {
                let leap = (self.year % 4 == 0 && self.year % 100 != 0) || self.year % 400 == 0;
                if leap {
                    29
                } else {
                    28
                }
            }
        }
    }

    /// Civil date from days since the Unix epoch (Howard Hinnant's algorithm).
    pub fn from_unix_days(days: i64) -> Self {
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
        let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
        Date {
            year: (if m <= 2 { y + 1 } else { y }) as i32,
            month: m,
            day: d,
        }
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

impl fmt::Debug for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::str::FromStr for Date {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        let bad = || crate::Error::Malformed {
            what: "date",
            detail: format!("'{s}' is not YYYY-MM-DD"),
        };
        let mut parts = s.trim().split('-');
        let year = parts.next().and_then(|p| p.parse().ok()).ok_or_else(bad)?;
        let month = parts.next().and_then(|p| p.parse().ok()).ok_or_else(bad)?;
        let day = parts.next().and_then(|p| p.parse().ok()).ok_or_else(bad)?;
        if parts.next().is_some() {
            return Err(bad());
        }
        Date::new(year, month, day)
    }
}

impl TryFrom<String> for Date {
    type Error = crate::Error;
    fn try_from(s: String) -> crate::Result<Self> {
        s.parse()
    }
}

impl From<Date> for String {
    fn from(d: Date) -> String {
        d.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_orders() {
        let a: Date = "2026-09-06".parse().unwrap();
        let b: Date = "2026-12-31".parse().unwrap();
        assert!(a < b);
        assert_eq!(a.to_string(), "2026-09-06");
        assert!("2026-02-30".parse::<Date>().is_err());
        assert!("2026-13-01".parse::<Date>().is_err());
        assert!("2024-02-29".parse::<Date>().is_ok());
    }

    #[test]
    fn epoch_conversion() {
        assert_eq!(Date::from_unix_days(0), Date::new(1970, 1, 1).unwrap());
        assert_eq!(Date::from_unix_days(20_702), Date::new(2026, 9, 6).unwrap());
    }
}
