// Copyright 2023 Mivik
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

use chrono::{DateTime, TimeZone, Utc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn system_time_to_tuple(t: &SystemTime) -> (i64, u32) {
    match t.duration_since(UNIX_EPOCH) {
        Ok(dur) => (dur.as_secs() as i64, dur.subsec_nanos()),
        Err(e) => {
            // unlikely but should be handled
            let dur = e.duration();
            let (sec, nsec) = (dur.as_secs() as i64, dur.subsec_nanos());
            if nsec == 0 {
                (-sec, 0)
            } else {
                (-sec - 1, 1_000_000_000 - nsec)
            }
        }
    }
}

pub fn tuple_to_system_time(time: (i64, u32)) -> SystemTime {
    let (secs, nsecs) = time;
    if secs >= 0 {
        UNIX_EPOCH + Duration::new(secs as u64, nsecs)
    } else if nsecs == 0 {
        UNIX_EPOCH - Duration::new((-secs) as u64, 0)
    } else {
        UNIX_EPOCH - Duration::new((-secs) as u64, 1_000_000_000 - nsecs)
    }
}

pub fn system_time_to_date_time(t: &SystemTime) -> DateTime<Utc> {
    let (secs, nsecs) = system_time_to_tuple(t);
    Utc.timestamp_opt(secs, nsecs).unwrap()
}

pub fn date_time_to_system_time(t: &DateTime<Utc>) -> SystemTime {
    let (secs, nsecs) = (t.timestamp(), t.timestamp_subsec_nanos());
    tuple_to_system_time((secs, nsecs))
}

pub fn unix_epoch_date_time() -> DateTime<Utc> {
    Utc.timestamp_opt(0, 0).unwrap()
}

pub mod compact_date_time {
    use chrono::{DateTime, TimeZone, Utc};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(val: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let tuple = (val.timestamp(), val.timestamp_subsec_nanos());
        tuple.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (secs, nsecs) = <(i64, u32)>::deserialize(deserializer)?;
        Ok(Utc.timestamp_opt(secs, nsecs).unwrap())
    }
}

pub mod opt_compact_date_time {
    use chrono::{DateTime, TimeZone, Utc};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(val: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let tuple = val.map(|val| (val.timestamp(), val.timestamp_subsec_nanos()));
        tuple.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let tuple = <Option<(i64, u32)>>::deserialize(deserializer)?;
        Ok(tuple.map(|it| Utc.timestamp_opt(it.0, it.1).unwrap()))
    }
}
