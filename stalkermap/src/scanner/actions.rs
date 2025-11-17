use std::collections::HashMap;

#[macro_export]
macro_rules! actions {
    ($($a:expr), * $(,)?) => {
        vec![$(Box::new($a) as Box<dyn Action>), *]
    }
}

pub trait Action: Send + Sync + 'static {
    fn name(&self) -> &'static str;

    fn set_read_from_successfull_connection(&self) -> bool;

    fn execute_after_successfull_connection(&self, actions_results: &mut HashMap<String, String>);

    fn execute_after_successfull_connection_and_read(
        &self,
        size_t_written: &usize,
        raw_data: &[u8],
        actions_results: &mut HashMap<String, String>,
    );
}

pub struct ActionIsPortOpen {}

impl Action for ActionIsPortOpen {
    fn name(&self) -> &'static str {
        "IsPortOpen"
    }
    fn set_read_from_successfull_connection(&self) -> bool {
        false
    }

    fn execute_after_successfull_connection(&self, actions_results: &mut HashMap<String, String>) {
        actions_results.insert(self.name().to_string(), "open".to_string());
    }

    fn execute_after_successfull_connection_and_read(
        &self,
        _size_t_written: &usize,
        _raw_data: &[u8],
        _actions_results: &mut HashMap<String, String>,
    ) {
    }
}
