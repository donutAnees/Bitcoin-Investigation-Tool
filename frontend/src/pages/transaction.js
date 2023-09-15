import { useLoaderData } from "react-router-dom";
import * as d3 from "d3";
import styles from "./transaction.module.css"
import { useEffect, useRef, useState } from "react";

export default function Transaction() {
  const ref = useRef();
  const rawHTML = useLoaderData();

  const [data, setData] = useState({
    nodes: [{ id: "A" }, { id: "B" }, { id: "C" }, { id: "D" }, { id: "E" }],
    links: [
      { source: "A", target: "B" },
      { source: "B", target: "C" },
      { source: "C", target: "D" },
      { source: "D", target: "E" },
      { source: "E", target: "A" },
    ],
  });

  useEffect(() => {
    const svg = d3.select(ref.current)
      .attr("viewBox", [-100 / 2, -100 / 2, 100, 100])

    const nodes = data.nodes;
    const links = data.links;

    const simulation = d3
      .forceSimulation(nodes)
      .force(
        "link",
        d3.forceLink(links).id((d) => d.id)
      )
      .force("charge", d3.forceManyBody().strength(-150))
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
      .attr("r", 5);

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
    <div className={styles.container}>
      <svg ref={ref}></svg>
    </div>
  );
  
}

export async function loader({ request, params }) {
  const hash = params.hash;
  const response = await fetch(
    "http://127.0.0.1:5000/transactionhash?hash=" + hash
  );
  const data = response.text();
  return data;
}
