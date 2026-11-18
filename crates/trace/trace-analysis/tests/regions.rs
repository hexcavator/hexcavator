//! Regions of interest: WPA's region files read, and start and stop events
//! paired into instances.

use hexcavator_etl::Guid;
use hexcavator_trace_analysis::regions::{Endpoint, Instance, Occurrence, Regions, instances};

const P: &str = "{11111111-2222-3333-4444-555555555555}";

fn provider() -> Guid {
    Guid::parse("11111111-2222-3333-4444-555555555555").unwrap()
}

/// A region file with `regions` (XML) under one root.
fn file(regions: &str) -> String {
    format!(
        r#"<?xml version='1.0' encoding='utf-8' standalone='yes'?>
<?Copyright (c) Microsoft Corporation. All rights reserved.?>
<InstrumentationManifest>
  <Instrumentation>
    <Regions>
      <RegionRoot Guid="{{EFA7A927-BAE3-48F6-92E1-000000000000}}" Name="Root" FriendlyName="The root">
        {regions}
      </RegionRoot>
    </Regions>
  </Instrumentation>
</InstrumentationManifest>"#
    )
}

fn event(id: u16, version: u8) -> String {
    format!(r#"<Event Provider="{P}" Id="{id}" Version="{version}" />"#)
}

/// An occurrence at `time` on thread `tid` with `fields`.
fn at(time: i64, tid: u32, fields: &[(&str, &str)]) -> Occurrence {
    Occurrence {
        time,
        process_id: 7,
        thread_id: tid,
        fields: fields
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect(),
        ..Occurrence::default()
    }
}

/// The occurrences of each event ID.
fn source(by_id: Vec<(u16, Vec<Occurrence>)>) -> impl Fn(&Endpoint) -> Vec<Occurrence> {
    move |e: &Endpoint| {
        assert_eq!(e.provider, provider());
        by_id
            .iter()
            .filter(|(id, _)| *id == e.id)
            .flat_map(|(_, o)| o.clone())
            .collect()
    }
}

fn spans(found: &[Instance], region: usize) -> Vec<(i64, i64, Option<String>)> {
    found
        .iter()
        .filter(|i| i.region == region)
        .map(|i| (i.start, i.stop, i.name.clone()))
        .collect()
}

#[test]
fn reads_the_documented_example() {
    // (WPA's documentation's sample.)
    let text = r#"<?xml version='1.0' encoding='utf-8' standalone='yes'?>
<InstrumentationManifest>
   <Instrumentation>
      <Regions>
         <RegionRoot Guid="{EFA7A927-BAE3-48F6-92E1-000000000000}" Name="Sample Region File Root" FriendlyName="Root">
            <Region Guid="{d8d639a0-cf4c-45fb-976a-000111000100}" Name="FastStartup-Suspend-UserSession-Shutdown" FriendlyName="User Session Shutdown">
               <Start><Event Provider="{dbe9b383-7cf3-4331-91cc-a3cb16a3b538}" Id="301" Version="0" /></Start>
               <Stop><Event Provider="{331c3b3a-2005-44c2-ac5e-77220c37d6b4}" Id="22" Version="0" /></Stop>
            </Region>
         </RegionRoot>
      </Regions>
   </Instrumentation>
</InstrumentationManifest>"#;
    let r = Regions::from_xml(text).unwrap();
    assert_eq!(r.regions.len(), 2);
    let root = &r.regions[0];
    assert_eq!(
        (root.name.as_str(), root.display_name(), root.parent),
        ("Sample Region File Root", "Root", None)
    );
    assert!(
        root.start.is_none() && root.unsupported.is_none(),
        "a container"
    );
    let s = &r.regions[1];
    assert_eq!(s.display_name(), "User Session Shutdown");
    assert_eq!(s.parent, Some(0));
    let start = s.start.as_ref().unwrap();
    assert_eq!((start.id, start.version), (301, 0));
    assert_eq!(
        start.provider,
        Guid::parse("dbe9b383-7cf3-4331-91cc-a3cb16a3b538").unwrap()
    );
    assert_eq!(s.stop.as_ref().unwrap().id, 22);
}

#[test]
fn pairs_by_thread_names_and_nests() {
    let text = file(&format!(
        r#"<Region Guid="{{A}}" Name="Work" FriendlyName="Work items">
             <Start>{}</Start><Stop>{}</Stop>
             <Match><Event TID="true" /></Match>
             <Naming><PayloadBased NameField="Item" /></Naming>
             <Region Guid="{{B}}" Name="Step">
               <Start>{}<PayloadIdentifier FieldName="Kind" FieldValue="step" /></Start>
               <Stop>{}</Stop>
               <Match><Event><Payload FieldName="Key" TargetFieldName="DoneKey" /></Event></Match>
             </Region>
           </Region>"#,
        event(1, 0),
        event(2, 0),
        event(3, 0),
        event(4, 0)
    ));
    let r = Regions::from_xml(&text).unwrap();
    assert_eq!(
        r.regions
            .iter()
            .map(|d| d.name.as_str())
            .collect::<Vec<_>>(),
        ["Root", "Work", "Step"]
    );
    assert_eq!(r.regions[2].parent, Some(1));
    let (found, unpaired) = instances(
        &r,
        source(vec![
            // Work: thread 1 nests two (inside out), thread 2 one; a stop
            // on thread 3 with no start; a start on thread 4 never stopped.
            (
                1,
                vec![
                    at(10, 1, &[("Item", "a")]),
                    at(20, 1, &[("Item", "b")]),
                    at(15, 2, &[("Item", "c")]),
                    at(90, 4, &[]),
                ],
            ),
            (
                2,
                vec![
                    at(30, 1, &[]),
                    at(40, 1, &[]),
                    at(35, 2, &[]),
                    at(50, 3, &[]),
                ],
            ),
            // Step: paired by Key = DoneKey; one start filtered out.
            (
                3,
                vec![
                    at(11, 1, &[("Kind", "step"), ("Key", "x")]),
                    at(12, 1, &[("Kind", "step"), ("Key", "y")]),
                    at(13, 1, &[("Kind", "other"), ("Key", "z")]),
                ],
            ),
            (
                4,
                vec![
                    at(14, 1, &[("DoneKey", "x")]),
                    at(16, 1, &[("DoneKey", "y")]),
                    at(17, 1, &[("DoneKey", "z")]),
                ],
            ),
        ]),
    );
    assert_eq!(
        spans(&found, 1),
        [
            (10, 40, Some("a".into())),
            (15, 35, Some("c".into())),
            (20, 30, Some("b".into()))
        ]
    );
    assert_eq!((unpaired[1].starts, unpaired[1].stops), (1, 1));
    assert_eq!(spans(&found, 2), [(11, 14, None), (12, 16, None)]);
    assert_eq!(
        (unpaired[2].starts, unpaired[2].stops),
        (0, 1),
        "z's start was filtered out"
    );
    // The root: a container from the first child start to the last stop.
    assert_eq!(spans(&found, 0), [(10, 40, None)]);
    // In start order.
    assert!(found.windows(2).all(|w| w[0].start <= w[1].start));
}

#[test]
fn does_not_contain_naming_from_the_stop_and_unsupported() {
    let text = file(&format!(
        r#"<Region Guid="{{A}}" Name="NotDebug">
             <Start>{}<PayloadIdentifier FieldName="Path" FieldValue="debug" FieldValueRelationship="DoesNotContain" /></Start>
             <Stop>{}</Stop>
             <Naming><PayloadBased NameField="Result" InstanceEndpoint="Stop" /></Naming>
           </Region>
           <Region Guid="{{B}}" Name="Timed"><Start><Duration Provider="{P}" Id="5" Version="0" Duration="Ms" /></Start><Stop>{}</Stop></Region>
           <Region Guid="{{C}}" Name="Nested"><Start>{}</Start><Stop>{}</Stop><Match><SelfNest TID="true" /></Match></Region>
           <Region Guid="{{D}}" Name="HalfOpen"><Start>{}</Start></Region>"#,
        event(1, 0),
        event(2, 0),
        event(2, 0),
        event(1, 0),
        event(2, 0),
        event(1, 0)
    ));
    let r = Regions::from_xml(&text).unwrap();
    let (found, _) = instances(
        &r,
        source(vec![
            (
                1,
                vec![
                    at(1, 1, &[("Path", "c:\\debug\\x")]),
                    at(3, 1, &[("Path", "c:\\release\\x"), ("Result", "start's")]),
                ],
            ),
            (2, vec![at(5, 1, &[("Result", "ok")])]),
        ]),
    );
    assert_eq!(
        spans(&found, 1),
        [(3, 5, Some("ok".into()))],
        "the debug start filtered; named from the stop"
    );
    for (i, what) in [(2, "Duration"), (3, "SelfNest"), (4, "without a stop")] {
        let u = r.regions[i].unsupported.as_deref().unwrap();
        assert!(u.contains(what), "{u}");
        assert!(spans(&found, i).is_empty());
    }
}

#[test]
fn malformed_files_are_errors() {
    assert!(Regions::from_xml("<Other/>").is_err());
    assert!(
        Regions::from_xml("<InstrumentationManifest/>").is_err(),
        "no regions"
    );
    assert!(
        Regions::from_xml(&file(r#"<Region Guid="{A}"><Start/></Region>"#)).is_err(),
        "no name"
    );
    assert!(
        Regions::from_xml(&file(
            r#"<Region Name="A"><Start><Event Id="1"/></Start></Region>"#
        ))
        .is_err(),
        "no provider"
    );
    assert!(
        Regions::from_xml(&file(&format!(
            r#"<Region Name="A"><Start><Event Provider="{P}" Id="x"/></Start></Region>"#
        )))
        .is_err()
    );
    assert!(
        Regions::from_xml(&file(&format!(
            r#"<Region Name="A"><Start><Event Provider="{P}" Id="99999"/></Start></Region>"#
        )))
        .is_err()
    );
    assert!(
        Regions::from_xml("<InstrumentationManifest").is_err(),
        "not XML"
    );
}
