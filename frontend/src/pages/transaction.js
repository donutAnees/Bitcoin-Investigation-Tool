import { useEffect, useMemo, useRef } from "react";
import { useLoaderData } from "react-router-dom";
import { Network } from "vis-network";

export default function Transaction() {
  const backendData = useLoaderData();  
  const visJsRef = useRef(null);
  const networkRef = useRef(null);

  const options = useMemo(() => {
    return {
      interaction: { hover: true },
      nodes: {
        shape: "dot",
      },
    };
  }, []);

  const prepareNetwork = (network, newData) => {
    console.log(newData)
    newData.nodes.forEach((element) => {
      network.body.data.nodes.update({
        id: element.id,
        value: element.title.details.total,
        title: `Block Height: ${element.title.details.blockheight}\n Total: ${element.title.details.total}\n Input: ${element.title.details.inputs}\n Output: ${element.title.details.outputs}\n Output Address:${element.title.details.output_address}\n Input Address:${element.title.details.input_address}`,
        color: "#e6ffda",
      });
    });

    newData.edges.forEach((element) => {
      network.body.data.edges.update({
        from: element.source,
        to: element.target,
        arrows: "middle",
      });
    });
  };

  useEffect(() => {
    const { nodes, edges } = backendData;

    networkRef.current =
      visJsRef.current &&
      new Network(visJsRef.current, { nodes, edges }, options);


    networkRef.current.body.data.nodes.update({
        id: nodes[0].id,
        color: "#e6ffda",
        value: nodes[0].total,
        title: `Block Height: ${nodes[0].blockheight}\n Total: ${nodes[0].total}\n Input: ${nodes[0].inputs}\n Output: ${nodes[0].outputs} \n Input Addresses: ${nodes[0].input_address}\n Output Address:${nodes[0].output_address}`,
      });

    networkRef.current.on("selectNode", async (event) => {
      const nodeID = event.nodes[0];
      const response = await fetch("http://127.0.0.1:5000/expand?id=" + nodeID);
      const newData = await response.json();

      prepareNetwork(networkRef.current, newData);
    });

    return () => {
      if (networkRef.current) {
        networkRef.current.destroy();
      }
    };
  }, [visJsRef, options, backendData]);

  const updateMixers = async () => {
    const response = await fetch("http://127.0.0.1:5000/mixers");
    const data = await response.json();
    //prepareNetwork(networkRef.current, data);
    console.log(data)
  };

  return (
    <div>
      <div
        className="text-center w-1/4 z-10 absolute left-1/2 transform -translate-x-1/2 text-black pt-2 pb-2 bg-white rounded-md mt-2 cursor-pointer"
        onClick={() => updateMixers()}
      >
        Find Mixers
      </div>
      <div className="w-screen h-screen bg-bluish-black" ref={visJsRef} />
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
