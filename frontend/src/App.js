import { createBrowserRouter } from "react-router-dom";
import { RouterProvider } from "react-router-dom";
import { loader as TransactionGraphLoader } from "./pages/transaction";
import Root from "./pages/root";
import Home from "./pages/home";
import Transaction from "./pages/transaction";

function App() {
  const router = createBrowserRouter([
    {
      path: "/",
      element: <Root/>,
      children: [
        {
          path: "/",
          element: <Home />,
        },
        {
          path: `/transaction/:hash`,
          element: <Transaction/>,
          loader: TransactionGraphLoader,
        },
      ],
    },
  ]);

  return (
    <div className="App">
      <RouterProvider router={router} />
    </div>
  );
}

export default App;
