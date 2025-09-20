use std::{fmt::Display, io};

pub enum Sanatize {
    MatchString(String),
    MatchStrings(Vec<String>),
    IsType(DesiredType),
}

enum FilterErrorMessage {
    NotNumber(DesiredType),
    NotString(DesiredType),
    NotBool(DesiredType),
    NotMatchString(String),
    NotMatchStrings(),
}

impl Display for FilterErrorMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotNumber(t) => {
                write!(f, "The value is not a {}, try again!", t)
            }
            Self::NotString(t) => {
                write!(f, "The value is not a {}, try again!", t)
            }
            Self::NotBool(t) => {
                write!(f, "The value is not a {}, try again!", t)
            }
            Self::NotMatchString(s) => {
                write!(f, "The value doesn't match with {}, try again!", s)
            }
            Self::NotMatchStrings() => {
                write!(f, "The value doesn't match with the options, try again!",)
            }
        }
    }
}

impl Sanatize {
    fn execute(answer: String, filters: &Vec<Sanatize>) -> Result<String, FilterErrorMessage> {
        let clean_answer = answer.trim();

        for filter in filters {
            match filter {
                Sanatize::IsType(t) => match t {
                    DesiredType::String => match clean_answer.parse::<String>() {
                        Ok(_) => {
                            continue;
                        }
                        Err(_) => return Err(FilterErrorMessage::NotString(DesiredType::String)),
                    },
                    DesiredType::Bool => match clean_answer.parse::<bool>() {
                        Ok(_) => {
                            continue;
                        }
                        Err(_) => return Err(FilterErrorMessage::NotBool(DesiredType::Bool)),
                    },
                    DesiredType::U8 => match clean_answer.parse::<u8>() {
                        Ok(_) => {
                            continue;
                        }
                        Err(_) => return Err(FilterErrorMessage::NotNumber(DesiredType::U8)),
                    },
                    DesiredType::U16 => match clean_answer.parse::<u16>() {
                        Ok(_) => {
                            continue;
                        }
                        Err(_) => return Err(FilterErrorMessage::NotNumber(DesiredType::U16)),
                    },
                    DesiredType::U32 => match clean_answer.parse::<u32>() {
                        Ok(_) => {
                            continue;
                        }
                        Err(_) => return Err(FilterErrorMessage::NotNumber(DesiredType::U32)),
                    },
                    DesiredType::U64 => match clean_answer.parse::<u64>() {
                        Ok(_) => {
                            continue;
                        }
                        Err(_) => return Err(FilterErrorMessage::NotNumber(DesiredType::U64)),
                    },
                    DesiredType::U128 => match clean_answer.parse::<u128>() {
                        Ok(_) => {
                            continue;
                        }
                        Err(_) => return Err(FilterErrorMessage::NotNumber(DesiredType::U128)),
                    },
                    DesiredType::I8 => match clean_answer.parse::<i8>() {
                        Ok(_) => {
                            continue;
                        }
                        Err(_) => return Err(FilterErrorMessage::NotNumber(DesiredType::I8)),
                    },
                    DesiredType::I16 => match clean_answer.parse::<i16>() {
                        Ok(_) => {
                            continue;
                        }
                        Err(_) => return Err(FilterErrorMessage::NotNumber(DesiredType::I16)),
                    },
                    DesiredType::I32 => match clean_answer.parse::<i32>() {
                        Ok(_) => {
                            continue;
                        }
                        Err(_) => return Err(FilterErrorMessage::NotNumber(DesiredType::I32)),
                    },
                    DesiredType::I64 => match clean_answer.parse::<i64>() {
                        Ok(_) => {
                            continue;
                        }
                        Err(_) => return Err(FilterErrorMessage::NotNumber(DesiredType::I64)),
                    },
                    DesiredType::I128 => match clean_answer.parse::<i128>() {
                        Ok(_) => {
                            continue;
                        }
                        Err(_) => return Err(FilterErrorMessage::NotNumber(DesiredType::I128)),
                    },
                },
                Sanatize::MatchString(s) => {
                    if clean_answer == s {
                        continue;
                    } else {
                        return Err(FilterErrorMessage::NotMatchString(s.to_string()));
                    }
                }
                Sanatize::MatchStrings(vector) => {
                    let mut found_match = false;

                    for word in vector {
                        if clean_answer == word {
                            found_match = true;
                            break;
                        } else {
                            continue;
                        }
                    }

                    if found_match == false {
                        return Err(FilterErrorMessage::NotMatchStrings());
                    } else {
                        continue;
                    }
                }
            };
        }
        Ok(clean_answer.to_string())
    }
}

pub enum DesiredType {
    String,
    Bool,
    U8,
    U16,
    U32,
    U64,
    U128,
    I8,
    I16,
    I32,
    I64,
    I128,
}

impl Display for DesiredType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String => write!(f, "string"),
            Self::Bool => write!(f, "bool"),
            Self::U8 => write!(f, "u8"),
            Self::U16 => write!(f, "u16"),
            Self::U32 => write!(f, "u32"),
            Self::U64 => write!(f, "u64"),
            Self::U128 => write!(f, "u128"),
            Self::I8 => write!(f, "i8"),
            Self::I16 => write!(f, "i16"),
            Self::I32 => write!(f, "i32"),
            Self::I64 => write!(f, "i64"),
            Self::I128 => write!(f, "i128"),
        }
    }
}

pub struct Terminal {
    pub answer: String,
}

/// Print a question to the terminal and loops it until it gets the desired answer
impl Terminal {
    pub fn ask(question: &str, filters: Vec<Sanatize>) -> Terminal {
        let answer: String = loop {
            println!("{}", question);
            let mut answer = String::new();

            match io::stdin().read_line(&mut answer) {
                Ok(_) => {
                    let sanatized_answer = Sanatize::execute(answer, &filters);

                    match sanatized_answer {
                        Ok(data) => break data,
                        Err(e) => {
                            println!("{}", e);
                            continue;
                        }
                    }
                }
                Err(_) => {
                    eprintln!("Couldn't read line..");
                    continue;
                }
            };
        };

        Terminal { answer: answer }
    }
}
