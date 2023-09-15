import { useLoaderData } from "react-router-dom";
import * as d3 from "d3";
import styles from "./transaction.module.css";
import { useEffect, useRef, useState } from "react";
import { TransformWrapper, TransformComponent } from "react-zoom-pan-pinch";

export default function Transaction() {
  const ref = useRef();
  const backend_data = useLoaderData();

  const [data, setData] = useState({
    nodes: backend_data.nodes,
    links: backend_data.edges,
  });

  useEffect(() => {
    const svg = d3
      .select(ref.current)
      .attr("viewBox", [-300 / 2, -300 / 2, 300, 300]);
    svg.selectAll("*").remove();

    const nodes = data.nodes;
    const links = data.links;

    const simulation = d3
      .forceSimulation(nodes)
      .force(
        "link",
        d3.forceLink(links).id((d) => d.id)
      )
      .force("charge", d3.forceManyBody().strength(-20))
      .force("x", d3.forceX())
      .force("y", d3.forceY());

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
      .attr("r", 3.5)
      .style("fill", "white")
      .on("click", async (nodeData) => {
        const clicked_node = nodeData.target.__data__.id;
        console.log(clicked_node);
        const response = await fetch(
          "http://127.0.0.1:5000/expand?id=" + clicked_node
        );
        const data = await response.json();
        setData({
          nodes: data.nodes,
          links: data.edges,
        });
      });

    simulation.on("tick", () => {
      link
        .attr("x1", (d) => d.source.x)
        .attr("y1", (d) => d.source.y)
        .attr("x2", (d) => d.target.x)
        .attr("y2", (d) => d.target.y);

      node.attr("cx", (d) => d.x).attr("cy", (d) => d.y);
    });
  }, [data]);

  return (
    <TransformWrapper>
      <div className={styles.container}>
        <TransformComponent>
          <svg ref={ref}></svg>
        </TransformComponent>
      </div>
    </TransformWrapper>
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
