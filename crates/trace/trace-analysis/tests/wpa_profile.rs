//! WPA profiles: both formats, read to views, graphs and presets.

use hexcavator_trace_analysis::wpa_profile::{Column, Profile};

/// A profile in the XAML format: a view of a sampled CPU graph (a typed
/// item) and a processes table (a generic item, by ClsID).
const XAML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<WpaProfile xmlns="clr-namespace:Microsoft.Performance.Shell;assembly=Microsoft.Performance.Shell" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
  <WpaProfile.Views>
    <AnalysisView Name="5984d89a-b545-4ba4-a5f4-555f7d9d94c2" IsVisible="True">
      <AnalysisView.Title><ViewTitle Title="CPU &amp; processes" /></AnalysisView.Title>
      <CpuSamplingGraphTreeItem GraphHeight="194">
        <CpuSamplingGraphTreeItem.HdvViewModelPreset>
          <HdvViewModelPreset Name="By Process, Stack" KeyColumnCount="2" InitialFilterQuery="[Process Name]:=&quot;app.exe&quot;">
            <HdvViewModelPreset.ConfigurableColumns>
              <HdvColumnViewModelPreset Guid="7EE6A5FF-1FAF-428A-A7C2-7D2CB2B5CF26" Name="Process Name" Width="200" IsVisible="True" SortPriority="2" />
              <HdvColumnViewModelPreset Guid="b8b3e2a8-6a49-4e8b-9a43-6c3e0b4e2e8a" Name="Stack" Width="200" />
              <HdvColumnViewModelPreset Guid="c8a9d8a4-56c4-4b8f-8b8e-6d7e3f0c2b1a" Name="Weight" SortOrder="Descending" SortPriority="0" AggregationMode="Sum" IsVisible="False" />
            </HdvViewModelPreset.ConfigurableColumns>
            <HdvViewModelPreset.HighlightEntries>
              <HighlightEntry StartTimeColumnName="Time" HighlightQuery="x" />
            </HdvViewModelPreset.HighlightEntries>
          </HdvViewModelPreset>
        </CpuSamplingGraphTreeItem.HdvViewModelPreset>
      </CpuSamplingGraphTreeItem>
      <Core4SummaryTableFillerGraphTreeItem ClsID="B186F02D-8D06-4BBB-9AD1-ABF7985FB61A">
        <Core4SummaryTableFillerGraphTreeItem.HdvViewModelPreset>
          <HdvViewModelPreset Name="Lifetime By Process" KeyColumnCount="1">
            <HdvViewModelPreset.ConfigurableColumns>
              <HdvColumnViewModelPreset Guid="1" Name="Process Name" />
            </HdvViewModelPreset.ConfigurableColumns>
          </HdvViewModelPreset>
        </Core4SummaryTableFillerGraphTreeItem.HdvViewModelPreset>
      </Core4SummaryTableFillerGraphTreeItem>
    </AnalysisView>
  </WpaProfile.Views>
</WpaProfile>"#;

/// The same in the container format (version 2).
const CONTAINER: &str = "\u{feff}<?xml version=\"1.0\" encoding=\"utf-8\"?>
<WpaProfileContainer xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" Version=\"2\" xmlns=\"http://tempuri.org/SerializableElement.xsd\">
  <Content xsi:type=\"WpaProfile2\">
    <Views>
      <View Guid=\"073bf55c-7d60-443c-b731-2028701a720b\" Title=\"Disk\">
        <Graphs>
          <Graph Guid=\"12C5387C-58CA-45D4-A5C6-450475C30E06\" GraphHeight=\"125\">
            <Preset Name=\"By Process, Path\" KeyColumnCount=\"2\" InitialFilterQuery=\"  \">
              <Columns>
                <Column Guid=\"A\" Name=\"Process Name\" IsVisible=\"true\" />
                <Column Guid=\"B\" Name=\"Path Name\" IsVisible=\"false\" SortPriority=\"1\" SortOrder=\"Ascending\" />
                <Column Guid=\"C\" Name=\"Size\" AggregationMode=\"Sum\" />
              </Columns>
              <HighlightEntries />
            </Preset>
          </Graph>
        </Graphs>
      </View>
      <View Title=\"Empty\" />
    </Views>
  </Content>
</WpaProfileContainer>";

#[test]
fn reads_the_xaml_format() {
    let p = Profile::from_xml(XAML).unwrap();
    assert_eq!(p.views.len(), 1);
    let v = &p.views[0];
    assert_eq!(v.title, "CPU & processes");
    assert_eq!(v.graphs.len(), 2);
    let cpu = &v.graphs[0];
    assert_eq!(cpu.item.as_deref(), Some("CpuSamplingGraphTreeItem"));
    assert_eq!(cpu.table, None);
    assert_eq!(cpu.preset.name, "By Process, Stack");
    assert_eq!(
        cpu.preset.filter.as_deref(),
        Some("[Process Name]:=\"app.exe\"")
    );
    assert_eq!(cpu.preset.highlights, 1);
    let keys: Vec<&str> = cpu.preset.keys().iter().map(|c| c.name.as_str()).collect();
    assert_eq!(keys, ["Process Name", "Stack"]);
    assert_eq!(
        cpu.preset.columns[2],
        Column {
            name: "Weight".into(),
            guid: "c8a9d8a4-56c4-4b8f-8b8e-6d7e3f0c2b1a".into(),
            visible: false,
            sort_priority: Some(0),
            descending: true,
            aggregation: Some("Sum".into()),
        }
    );
    assert_eq!(
        cpu.preset.columns[0].guid, "7ee6a5ff-1faf-428a-a7c2-7d2cb2b5cf26",
        "lowercase"
    );
    assert!(cpu.preset.columns[1].visible, "shown unless it says");
    let processes = &v.graphs[1];
    assert_eq!(
        processes.table.as_deref(),
        Some("b186f02d-8d06-4bbb-9ad1-abf7985fb61a")
    );
    assert_eq!(processes.preset.highlights, 0);
}

#[test]
fn reads_the_container_format() {
    let p = Profile::from_xml(CONTAINER).unwrap();
    assert_eq!(p.views.len(), 2);
    assert_eq!(p.views[0].title, "Disk");
    assert!(p.views[1].graphs.is_empty());
    let g = &p.views[0].graphs[0];
    assert_eq!(
        g.table.as_deref(),
        Some("12c5387c-58ca-45d4-a5c6-450475c30e06")
    );
    assert_eq!(g.item, None);
    assert_eq!(g.preset.filter, None, "a blank filter is none");
    assert_eq!(g.preset.key_columns, 2);
    assert!(!g.preset.columns[1].visible);
    assert_eq!(g.preset.columns[1].sort_priority, Some(1));
    assert!(!g.preset.columns[1].descending);
}

#[test]
fn other_documents_are_errors() {
    assert!(
        Profile::from_xml("<Regions/>")
            .unwrap_err()
            .contains("Regions")
    );
    assert!(Profile::from_xml("<WpaProfile").is_err());
    // A key count past its columns is all of them.
    let p = Profile::from_xml(
        r#"<WpaProfileContainer><Content><Views><View Title="v"><Graphs><Graph Guid="x"><Preset Name="p" KeyColumnCount="9"><Columns><Column Name="a"/></Columns></Preset></Graph></Graphs></View></Views></Content></WpaProfileContainer>"#,
    )
    .unwrap();
    assert_eq!(p.views[0].graphs[0].preset.keys().len(), 1);
}
