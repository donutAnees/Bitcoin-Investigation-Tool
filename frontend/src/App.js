import { createBrowserRouter } from "react-router-dom";
import { RouterProvider } from "react-router-dom";
import { loader as transactionGraphLoader } from "./pages/transaction";
import Root from "./pages/root";
import Transaction from "./pages/transaction";
import Home from "./pages/home";

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
          loader: transactionGraphLoader,
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
