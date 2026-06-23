//! [`MixinInteractionGraph`] — queryable graph over mixin facts.
//!
//! Built after collection from class models and analysis edges. Supports export
//! to JSON/DOT for reports and future Evidence Graph integration.

use std::collections::BTreeMap;

use crate::model::{
    ConflictEdgeType, GraphEdge, GraphNode, MixinClassRecord, MixinConflictEdgeRecord,
    MixinGraphExport, MixinInteractionRecord, MixinPriorityConflictRecord,
};

/// In-memory mixin interaction graph.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MixinInteractionGraph {
    nodes: BTreeMap<String, GraphNode>,
    edges: Vec<GraphEdge>,
}

impl MixinInteractionGraph {
    /// Build a graph from mixin class records and derived analysis artifacts.
    pub fn build(
        classes: &[MixinClassRecord],
        interactions: &[MixinInteractionRecord],
        conflict_edges: &[MixinConflictEdgeRecord],
        priority_conflicts: &[MixinPriorityConflictRecord],
    ) -> Self {
        let mut graph = Self::default();

        for class in classes {
            let node_id = format!("mixin:{}", class.class_name);
            graph.nodes.insert(
                node_id.clone(),
                GraphNode {
                    id: node_id,
                    label: class.class_name.clone(),
                    node_type: "mixin".to_string(),
                    mod_id: Some(class.mod_id.clone()),
                },
            );
            for target in &class.targets {
                let target_id = format!("target:{target}");
                graph.nodes.entry(target_id.clone()).or_insert(GraphNode {
                    id: target_id.clone(),
                    label: target.clone(),
                    node_type: "target".to_string(),
                    mod_id: None,
                });
                graph.edges.push(GraphEdge {
                    from: format!("mixin:{}", class.class_name),
                    to: target_id,
                    label: "targets".to_string(),
                    strength: 1,
                });
            }
        }

        for edge in conflict_edges {
            let from = format!("mixin:{}", edge.source_mixin);
            let to = format!("mixin:{}", edge.target_mixin);
            graph.edges.push(GraphEdge {
                from,
                to,
                label: edge.edge_type.as_str().to_string(),
                strength: edge.strength,
            });
        }

        for interaction in interactions {
            graph.edges.push(GraphEdge {
                from: format!("mixin:{}", interaction.mixin_a),
                to: format!("mixin:{}", interaction.mixin_b),
                label: interaction.interaction_type.as_str().to_string(),
                strength: interaction.strength,
            });
        }

        for conflict in priority_conflicts {
            graph.edges.push(GraphEdge {
                from: format!("mixin:{}", conflict.mixin_a),
                to: format!("mixin:{}", conflict.mixin_b),
                label: "priority-conflict".to_string(),
                strength: 50,
            });
        }

        graph
    }

    /// Export nodes and edges for CLI / reports.
    pub fn export(&self) -> MixinGraphExport {
        MixinGraphExport {
            nodes: self.nodes.values().cloned().collect(),
            edges: self.edges.clone(),
        }
    }

    /// Render a GraphML document for Gephi / yEd import.
    pub fn to_graphml(&self) -> String {
        let mut out = String::from(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<graphml xmlns="http://graphml.graphdrawing.org/xmlns">
  <key id="label" for="node" attr.name="label" attr.type="string"/>
  <key id="type" for="node" attr.name="type" attr.type="string"/>
  <key id="mod" for="node" attr.name="mod" attr.type="string"/>
  <key id="elabel" for="edge" attr.name="label" attr.type="string"/>
  <key id="strength" for="edge" attr.name="strength" attr.type="int"/>
  <graph edgedefault="directed">
"#,
        );
        for node in self.nodes.values() {
            let label = xml_escape(&node.label);
            let mod_id = node.mod_id.as_deref().unwrap_or("");
            out.push_str(&format!(
                r#"    <node id="{id}">
      <data key="label">{label}</data>
      <data key="type">{typ}</data>
      <data key="mod">{mod_id}</data>
    </node>
"#,
                id = xml_escape(&node.id),
                typ = xml_escape(&node.node_type),
            ));
        }
        for (idx, edge) in self.edges.iter().enumerate() {
            out.push_str(&format!(
                r#"    <edge id="e{idx}" source="{from}" target="{to}">
      <data key="elabel">{label}</data>
      <data key="strength">{strength}</data>
    </edge>
"#,
                from = xml_escape(&edge.from),
                to = xml_escape(&edge.to),
                label = xml_escape(&edge.label),
                strength = edge.strength,
            ));
        }
        out.push_str("  </graph>\n</graphml>\n");
        out
    }

    /// A **self-contained** interactive force-directed graph — no CDN, no network,
    /// no external scripts: a small vanilla-JS spring-electrical simulation drawn on
    /// a `<canvas>`, with drag, hover tooltips, per-edge-type filters, node search,
    /// and a node-type legend. Safe to open offline or commit as an artifact.
    pub fn to_html(&self, title: &str) -> String {
        let nodes_json = serde_json::to_string(
            &self
                .nodes
                .values()
                .map(|n| {
                    serde_json::json!({
                        "id": n.id,
                        "label": n.label,
                        "group": n.node_type,
                        "mod": n.mod_id,
                    })
                })
                .collect::<Vec<_>>(),
        )
        .unwrap_or_else(|_| "[]".into());
        let edges_json = serde_json::to_string(
            &self
                .edges
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "from": e.from,
                        "to": e.to,
                        "label": e.label,
                        "value": e.strength,
                    })
                })
                .collect::<Vec<_>>(),
        )
        .unwrap_or_else(|_| "[]".into());
        GRAPH_HTML_TEMPLATE
            .replace("__TITLE__", &html_escape(title))
            .replace("__NODES__", &nodes_json)
            .replace("__EDGES__", &edges_json)
    }

    /// Render a Graphviz DOT representation for external visualization.
    pub fn to_dot(&self) -> String {
        let mut out = String::from("digraph mixin_interactions {\n");
        for node in self.nodes.values() {
            let label = node.label.replace('"', "\\\"");
            out.push_str(&format!(
                "  \"{}\" [label=\"{}\" shape={}];\n",
                node.id,
                label,
                if node.node_type == "target" {
                    "box"
                } else {
                    "ellipse"
                }
            ));
        }
        for edge in &self.edges {
            out.push_str(&format!(
                "  \"{}\" -> \"{}\" [label=\"{}\"];\n",
                edge.from, edge.to, edge.label
            ));
        }
        out.push_str("}\n");
        out
    }

    /// Number of nodes in the graph.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of edges in the graph.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

impl ConflictEdgeType {
    pub fn as_str(self) -> &'static str {
        match self {
            ConflictEdgeType::SameInjectionPoint => "same-injection-point",
            ConflictEdgeType::ShadowAddedMember => "shadow-added-member",
            ConflictEdgeType::OverwriteCollision => "overwrite-collision",
            ConflictEdgeType::PriorityConflict => "priority-conflict",
            ConflictEdgeType::SharedTarget => "shared-target",
            ConflictEdgeType::NamespaceMismatch => "namespace-mismatch",
            ConflictEdgeType::InheritedTarget => "inherited-target",
            ConflictEdgeType::OverwritesSameMethod => "overwrites-same-method",
            ConflictEdgeType::RedirectsSameCall => "redirects-same-call",
            ConflictEdgeType::ModifiesSameLocal => "modifies-same-local",
            ConflictEdgeType::ChainedInjection => "chained-injection",
            ConflictEdgeType::ShadowDescriptorConflict => "shadow-descriptor-conflict",
            ConflictEdgeType::AccessorConflict => "accessor-conflict",
            ConflictEdgeType::OverwriteVsInjector => "overwrite-vs-injector",
            ConflictEdgeType::CancellableHeadVsReturn => "cancellable-head-vs-return",
            ConflictEdgeType::RedirectVsWrapOperation => "redirect-vs-wrap-operation",
            ConflictEdgeType::WrapConditionSuppressesCall => "wrap-condition-suppresses-call",
            ConflictEdgeType::ModifyArgsSameInvocation => "modify-args-same-invocation",
            ConflictEdgeType::UniqueMemberConflict => "unique-member-conflict",
        }
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Self-contained interactive graph page. `__TITLE__`, `__NODES__`, `__EDGES__`
/// are substituted at render time; everything else (layout simulation, drawing,
/// filters, search) is inline vanilla JS with no external dependency.
const GRAPH_HTML_TEMPLATE: &str = r##"<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"/>
<title>__TITLE__</title>
<style>
  html,body{height:100%;margin:0;font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6}
  #wrap{display:flex;height:100%}
  #side{width:260px;padding:12px;box-sizing:border-box;overflow:auto;background:#171a21;border-right:1px solid #2a2f3a}
  #side h1{font-size:15px;margin:0 0 10px}
  #side h2{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:#8a93a6;margin:16px 0 6px}
  #search{width:100%;padding:6px;box-sizing:border-box;background:#0f1115;border:1px solid #2a2f3a;color:#e6e6e6;border-radius:4px}
  .row{display:flex;align-items:center;gap:6px;font-size:12px;margin:3px 0;cursor:pointer}
  .swatch{width:11px;height:11px;border-radius:2px;flex:0 0 auto}
  canvas{flex:1;display:block;cursor:grab}
  #tip{position:fixed;pointer-events:none;background:#000d;border:1px solid #2a2f3a;padding:4px 7px;border-radius:4px;font-size:12px;display:none;max-width:320px}
  .muted{color:#8a93a6}
</style></head><body>
<div id="wrap">
  <div id="side">
    <h1>__TITLE__</h1>
    <input id="search" placeholder="search mod / mixin…"/>
    <div class="muted" id="counts" style="margin-top:8px;font-size:12px"></div>
    <h2>Node types</h2><div id="legend"></div>
    <h2>Edge types</h2><div id="filters"></div>
  </div>
  <canvas id="c"></canvas>
</div>
<div id="tip"></div>
<script>
const DATA = { nodes: __NODES__, edges: __EDGES__ };
const palette = ["#6ea8fe","#ff7b72","#3fb950","#d29922","#bc8cff","#56d4dd","#f778ba","#a5d6ff"];
const groups = [...new Set(DATA.nodes.map(n=>n.group||"node"))];
const groupColor = g => palette[groups.indexOf(g) % palette.length];
const edgeTypes = [...new Set(DATA.edges.map(e=>e.label||"edge"))].sort();
const edgeColor = t => palette[(edgeTypes.indexOf(t)+3) % palette.length];

const byId = new Map(DATA.nodes.map(n=>[n.id,n]));
DATA.nodes.forEach(n=>{n.deg=0});
DATA.edges.forEach(e=>{const a=byId.get(e.from),b=byId.get(e.to); if(a)a.deg++; if(b)b.deg++;});

const canvas=document.getElementById("c"), ctx=canvas.getContext("2d");
let W=0,H=0,scale=1,ox=0,oy=0;
function resize(){W=canvas.width=canvas.clientWidth;H=canvas.height=canvas.clientHeight;}
window.addEventListener("resize",resize); resize();

// Initial layout: spread on a circle so the simulation untangles quickly.
DATA.nodes.forEach((n,i)=>{const a=2*Math.PI*i/DATA.nodes.length;
  n.x=W/2+Math.cos(a)*Math.min(W,H)*0.3; n.y=H/2+Math.sin(a)*Math.min(W,H)*0.3; n.vx=0; n.vy=0;});

const active=new Set(edgeTypes);     // visible edge types
let query="";

function step(){
  // Spring-electrical: O(n^2) repulsion + edge attraction + weak centering.
  const k=Math.sqrt((W*H)/(DATA.nodes.length+1));
  for(let i=0;i<DATA.nodes.length;i++){
    const a=DATA.nodes[i];
    for(let j=i+1;j<DATA.nodes.length;j++){
      const b=DATA.nodes[j]; let dx=a.x-b.x,dy=a.y-b.y; let d=Math.hypot(dx,dy)||0.01;
      const rep=(k*k)/d/d*40; dx/=d; dy/=d;
      a.vx+=dx*rep; a.vy+=dy*rep; b.vx-=dx*rep; b.vy-=dy*rep;
    }
    a.vx+=(W/2-a.x)*0.002; a.vy+=(H/2-a.y)*0.002;
  }
  DATA.edges.forEach(e=>{const a=byId.get(e.from),b=byId.get(e.to); if(!a||!b)return;
    let dx=b.x-a.x,dy=b.y-a.y; let d=Math.hypot(dx,dy)||0.01; const f=(d-k)*0.01; dx/=d; dy/=d;
    a.vx+=dx*f; a.vy+=dy*f; b.vx-=dx*f; b.vy-=dy*f;});
  DATA.nodes.forEach(n=>{ if(n===dragging)return; n.x+=n.vx*=0.85; n.y+=n.vy*=0.85;});
}

function matches(n){return query && ((n.label||"").toLowerCase().includes(query) || (n.mod||"").toLowerCase().includes(query));}

function draw(){
  ctx.setTransform(scale,0,0,scale,ox,oy); ctx.clearRect(-ox/scale,-oy/scale,W/scale,H/scale);
  ctx.lineWidth=1;
  DATA.edges.forEach(e=>{ if(!active.has(e.label||"edge"))return;
    const a=byId.get(e.from),b=byId.get(e.to); if(!a||!b)return;
    ctx.strokeStyle=edgeColor(e.label||"edge"); ctx.globalAlpha=0.5;
    ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y); ctx.stroke();
  });
  ctx.globalAlpha=1;
  DATA.nodes.forEach(n=>{ const r=5+Math.min(n.deg,10);
    ctx.beginPath(); ctx.arc(n.x,n.y,r,0,2*Math.PI);
    ctx.fillStyle=groupColor(n.group||"node");
    ctx.globalAlpha = (query && !matches(n)) ? 0.2 : 1;
    ctx.fill(); if(matches(n)){ctx.lineWidth=2;ctx.strokeStyle="#fff";ctx.stroke();}
    ctx.fillStyle="#e6e6e6"; ctx.font="11px system-ui";
    ctx.fillText(n.label||n.id, n.x+r+2, n.y+3);
  });
  ctx.globalAlpha=1;
}
function frame(){step();draw();requestAnimationFrame(frame);} frame();

// ── interaction: drag nodes, pan, zoom, hover tooltip ──
let dragging=null, panning=false, last=null;
const tip=document.getElementById("tip");
function world(ev){const r=canvas.getBoundingClientRect(); return {x:(ev.clientX-r.left-ox)/scale,y:(ev.clientY-r.top-oy)/scale};}
function pick(p){let best=null,bd=1e9; DATA.nodes.forEach(n=>{const d=Math.hypot(n.x-p.x,n.y-p.y); const r=5+Math.min(n.deg,10); if(d<r+3&&d<bd){bd=d;best=n;}}); return best;}
canvas.addEventListener("mousedown",ev=>{const p=world(ev); dragging=pick(p); if(!dragging){panning=true;last={x:ev.clientX,y:ev.clientY};}});
canvas.addEventListener("mousemove",ev=>{
  if(dragging){const p=world(ev); dragging.x=p.x; dragging.y=p.y; dragging.vx=dragging.vy=0; return;}
  if(panning){ox+=ev.clientX-last.x; oy+=ev.clientY-last.y; last={x:ev.clientX,y:ev.clientY}; return;}
  const n=pick(world(ev));
  if(n){tip.style.display="block";tip.style.left=(ev.clientX+12)+"px";tip.style.top=(ev.clientY+12)+"px";
    tip.innerHTML="<b>"+(n.label||n.id)+"</b>"+(n.mod?"<br>mod: "+n.mod:"")+"<br>type: "+(n.group||"node")+" · degree "+n.deg;}
  else tip.style.display="none";
});
window.addEventListener("mouseup",()=>{dragging=null;panning=false;});
canvas.addEventListener("wheel",ev=>{ev.preventDefault();const f=ev.deltaY<0?1.1:0.9;scale*=f;},{passive:false});

// ── side panel: legend, edge filters, search, counts ──
const legend=document.getElementById("legend");
groups.forEach(g=>{const d=document.createElement("div");d.className="row";
  d.innerHTML='<span class="swatch" style="background:'+groupColor(g)+'"></span>'+g; legend.appendChild(d);});
const filters=document.getElementById("filters");
edgeTypes.forEach(t=>{const d=document.createElement("label");d.className="row";
  d.innerHTML='<input type="checkbox" checked><span class="swatch" style="background:'+edgeColor(t)+'"></span>'+t;
  d.querySelector("input").addEventListener("change",e=>{e.target.checked?active.add(t):active.delete(t);});
  filters.appendChild(d);});
document.getElementById("search").addEventListener("input",e=>{query=e.target.value.trim().toLowerCase();});
document.getElementById("counts").textContent=DATA.nodes.length+" nodes · "+DATA.edges.length+" edges";
</script></body></html>
"##;

impl crate::model::InteractionType {
    pub fn as_str(self) -> &'static str {
        match self {
            crate::model::InteractionType::DirectInjection => "direct-injection",
            crate::model::InteractionType::IndirectShadow => "indirect-shadow",
            crate::model::InteractionType::SharedMember => "shared-member",
            crate::model::InteractionType::PriorityOrder => "priority-order",
            crate::model::InteractionType::OverwriteStack => "overwrite-stack",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MixinClassRecord, MixinOperation, ResolvedInjectionPoint};
    use crate::refmap::Namespace;

    fn sample_class(mod_id: &str, mixin: &str, target: &str) -> MixinClassRecord {
        MixinClassRecord {
            archive: format!("{mod_id}.jar"),
            mod_id: mod_id.into(),
            config: "mixins.json".into(),
            class_name: mixin.into(),
            class_path: format!("{mixin}.class"),
            targets: vec![target.into()],
            target_namespace: Default::default(),
            runtime_namespace: Default::default(),
            operations: vec![MixinOperation::Inject],
            injected_methods: Vec::new(),
            shadows: Vec::new(),
            added_members: Vec::new(),
            calls: Vec::new(),
            handler_bodies: Vec::new(),
            target_hierarchy: Vec::new(),
            priority: 1000,
            refmap: None,
            hot_paths: Vec::new(),
            effects: Vec::new(),
            plugin_gated: false,
            side: crate::model::Side::Both,
            activation: crate::model::ActivationStatus::ActiveAssumed,
            activation_reason: String::new(),
        }
    }

    #[test]
    fn html_export_is_self_contained_and_interactive() {
        let classes = vec![sample_class("alpha", "alpha.Mixin", "net.minecraft.T")];
        let html = MixinInteractionGraph::build(&classes, &[], &[], &[]).to_html("My Pack");
        // Self-contained: no external scripts / network fetches of any kind.
        assert!(!html.contains("http://") && !html.contains("https://"));
        assert!(!html.contains("<script src"));
        // Title is injected and escaped; data is inlined; interactivity is present.
        assert!(html.contains("My Pack"));
        assert!(html.contains("alpha.Mixin"));
        assert!(html.contains("<canvas"));
        assert!(html.contains("search")); // node search control
        assert!(html.contains("Edge types")); // edge-type filters
        // No leftover template placeholders.
        assert!(!html.contains("__NODES__") && !html.contains("__TITLE__"));
    }

    #[test]
    fn html_export_escapes_title() {
        let html = MixinInteractionGraph::default().to_html("<script>x</script>");
        assert!(!html.contains("<script>x"));
        assert!(html.contains("&lt;script&gt;x"));
    }

    #[test]
    fn build_creates_mixin_and_target_nodes() {
        let classes = vec![sample_class("alpha", "alpha.Mixin", "net.minecraft.T")];
        let graph = MixinInteractionGraph::build(&classes, &[], &[], &[]);
        assert!(graph.node_count() >= 2);
        assert!(graph.edge_count() >= 1);
        let dot = graph.to_dot();
        assert!(dot.contains("digraph mixin_interactions"));
        assert!(dot.contains("alpha.Mixin"));
    }

    #[test]
    fn export_round_trips_node_and_edge_counts() {
        let mut a = sample_class("alpha", "alpha.Mixin", "net.minecraft.T");
        a.injected_methods.push(ResolvedInjectionPoint {
            target: "net.minecraft.T".into(),
            original: "tick()V".into(),
            resolved: "tick()V".into(),
            canonical: "tick()V".into(),
            site_key: "tick()V@HEAD".into(),
            namespace: Namespace::Named,
            injection_type: "inject".into(),
            resolved_via_refmap: false,
            handler_method: "handler".into(),
            handler_descriptor: String::new(),
            mutates_target_local: false,
            at_target: "HEAD".into(),
            at_detail: "HEAD".into(),
            impact: "entry-hook".into(),
            local_index: None,
            local_capture: String::new(),
            meta: Default::default(),
            at_ordinal: None,
            at_target_member: String::new(),
        });
        let graph = MixinInteractionGraph::build(&[a], &[], &[], &[]);
        let export = graph.export();
        assert!(!export.nodes.is_empty());
        assert!(!export.edges.is_empty());
        let json = serde_json::to_string(&export).expect("graph json");
        assert!(json.contains("alpha.Mixin"));
    }

    #[test]
    fn xml_escape_quotes_ampersands() {
        assert_eq!(xml_escape("a&b\"c"), "a&amp;b&quot;c");
    }
}
