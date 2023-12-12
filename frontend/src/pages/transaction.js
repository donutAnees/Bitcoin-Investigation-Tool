import { useLoaderData } from "react-router-dom";
import { useRef, useEffect, useMemo } from "react";
import { Network } from "vis-network";

//Sigh i hate commenting, but here we go guys

export default function Transaction() {
  const backendData = useLoaderData();

  //Made a ref to access the DOM Element

  //each node has a title field which will be displayed when hovered, make sure the required vis-network.min.css file link is given in the public html

  const visJsRef = useRef(null);
  //adding hover interaction
  const options = useMemo(() => {
    return {
      interaction: { hover: true },
      nodes: {
        //shape must be specified for the scaling to work
        shape: "dot",
        // scaling: {
        //   min: 10,
        //   max: 30,
        //   customScalingFunction: function (min, max, total, value) {
        //     if (max === min) {
        //       return 0.5;
        //     } else {
        //       let scale = 1 / (max - min);
        //       return Math.max(0, (value - min) * scale);
        //     }
        //   },
        // },
      },
    };
  }, []);

  useEffect(() => {
    const { nodes, edges } = backendData;

    const network =
      visJsRef.current &&
      new Network(visJsRef.current, { nodes, edges }, options);
    //updated the first node to display the color i want
    network.body.data.nodes.update({
      id: nodes[0].id,
      color: "#FB7E81",
    });

    network.on("selectNode", async (event) => {
      //get selectedNode ID
      const nodeID = event.nodes[0];
      const response = await fetch("http://127.0.0.1:5000/expand?id=" + nodeID);
      const newData = await response.json();

      newData.nodes.forEach((element) => {
        network.body.data.nodes.update({
          id: element.id,
          value: element.title.details.total,
          title: element.title.details.total,
          color: "#FB7E81",
        });
        console.log(element);
      });

      newData.edges.forEach((element) => {
        network.body.data.edges.update({
          from: element.source,
          to: element.target,
          arrows: "middle",
        });
      });
    });
  }, [visJsRef, options, backendData]);

  return <div className="w-screen h-screen bg-bluish-black" ref={visJsRef} />;
}

export async function loader({ request, params }) {
  const hash = params.hash;
  const response = await fetch(
    "http://127.0.0.1:5000/transactionhash?hash=" + hash
  );
  const data = await response.json();
  return data;
}
