import { useLoaderData } from "react-router-dom";
import * as d3 from "d3";
import styles from "./transaction.module.css";
import { useEffect, useRef, useState } from "react";
import { zoom, zoomIdentity } from "d3-zoom"; // Import d3-zoom

export default function Transaction() {
  const ref = useRef();
  const backend_data = useLoaderData();

  const [data, setData] = useState({
    nodes: backend_data.nodes,
    links: backend_data.edges,
  });

  const [hoveredNode, setHoveredNode] = useState(null);
  const [hoveredNodePosition, setHoveredNodePosition] = useState({
    x: 0,
    y: 0,
  });

  useEffect(() => {
    const svg = d3.select(ref.current).attr("viewBox", [-150, -150, 300, 300]);

    svg.selectAll("*").remove();

    const nodes = data.nodes;
    const links = data.links;

    const simulation = d3
      .forceSimulation(nodes)
      .force(
        "link",
        d3.forceLink(links).id((d) => d.id)
      )
      .force("charge", d3.forceManyBody().strength(-80))
      .force("x", d3.forceX())
      .force("y", d3.forceY());

    const drag = d3
      .drag()
      .on("start", (event, d) => {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
      })
      .on("drag", (event, d) => {
        d.fx = event.x;
        d.fy = event.y;
      })
      .on("end", (event, d) => {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      });

    const link = svg
      .append("g")
      .attr("stroke", "#999")
      .attr("stroke-opacity", 0.4)
      .selectAll("line")
      .data(links)
      .join("line")
      .attr("stroke-width", (d) => Math.sqrt(d.value));

    const node = svg
      .append("g")
      .selectAll("circle")
      .data(nodes)
      .join("circle")
      .attr("r", 5)
      .style("fill", "white")
      .on("click", async (nodeData) => {
        const clicked_node = nodeData.target.__data__.id;
        const response = await fetch(
          "http://127.0.0.1:5000/expand?id=" + clicked_node
        );
        const data = await response.json();
        setData({
          nodes: data.nodes,
          links: data.edges,
        });
      })
      .on("mouseover", (nodeData) => {
        const hover_node_data = nodeData.target.__data__;
        const X = nodeData.clientX;
        const Y = nodeData.clientY;
        setHoveredNode(hover_node_data);
        setHoveredNodePosition({ x: X, y: Y });
      })
      .on("mouseout", () => {
        setHoveredNode(null);
        setHoveredNodePosition({ x: 0, y: 0 });
      })
      .call(drag);

    simulation.on("tick", () => {
      link
        .attr("x1", (d) => d.source.x)
        .attr("y1", (d) => d.source.y)
        .attr("x2", (d) => d.target.x)
        .attr("y2", (d) => d.target.y);

      node.attr("cx", (d) => d.x).attr("cy", (d) => d.y);
    });

    const zoomBehavior = zoom()
      .scaleExtent([0.1, 10])
      .on("zoom", (event) => {
        svg.selectAll("g").attr("transform", event.transform);
      });

    svg.call(zoomBehavior);
    svg.call(zoomBehavior.transform, zoomIdentity);
  }, [data]);

  return (
    <div className={styles.container}>
      <svg ref={ref}></svg>
      {hoveredNode && (
        <div
          className={styles.hoveredNodeBox}
          style={{
            position: "absolute",
            fontSize: "0.75rem",
            left: hoveredNodePosition.x + 10 + "px",
            top: hoveredNodePosition.y + 10 + "px",
            background: "rgba(255, 255, 255, 0.9)",
            padding: "8px",
            border: "1px solid #ccc",
            borderRadius: "4px",
            boxShadow: "2px 2px 5px rgba(0, 0, 0, 0.3)",
          }}
        >
          <p>ID: {hoveredNode.id}</p>
          {hoveredNode.out_addresses && (
            <p>Out Addresses: {hoveredNode.out_addresses}</p>
          )}
          {hoveredNode.out_value && <p>Out Value: {hoveredNode.out_value}</p>}
          {hoveredNode.in_addresses && (
            <p>Addresses: {hoveredNode.in_addresses}</p>
          )}
          {hoveredNode.in_age && <p>In Age: {hoveredNode.in_age}</p>}
          {hoveredNode.in_output_value && (
            <p>Output Value: {hoveredNode.in_output_value}</p>
          )}
          {hoveredNode.in_sequence && (
            <p>Sequence: {hoveredNode.in_sequence}</p>
          )}
        </div>
      )}
    </div>
  );
}

export async function loader({ request, params }) {
  const hash = params.hash;
  const response = await fetch(
    "http://127.0.0.1:5000/transactionhash?hash=" + hash
  );
  const data = await response.json();
  return data;
}
