import { useLoaderData } from "react-router-dom";

export default function Transaction() {
  const rawHTML = useLoaderData();
  return (
    <>
      {
        <iframe
          srcDoc={rawHTML}
          title="Graph"
          width="1700px"
          height="1000px" // Adjust the height as needed
        ></iframe>
      }
    </>
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
