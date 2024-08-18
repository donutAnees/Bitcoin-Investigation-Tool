import Navbar from "../components/navbar";
import React, { useState } from "react";
import ResultDisplay from "./ResultDisplay";
export default function Wallet() {
  const [inputValue, setInputValue] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [legalStatus, setLegalStatus] = useState(null);
  const handleInputChange = (event) => {
    const value = event.target.value;
    setInputValue(value);
    if (value === "") {
      setSubmitted(false);
      setLegalStatus(null);
    }
  };
  const handleSubmit = async () => {
    const response = await fetch(
      "http://127.0.0.1:5000/wallet?id=" + inputValue
    );
    const status = await response.json();
    setLegalStatus(status.status === "legal");
    // console.log(status);
    setSubmitted(true);
  };

  return (
    <div className="bg-slate-50 dark:bg-bluish-black h-screen bg-light-bg dark:bg-dark-bg absolute bg-cover w-screen">
      <Navbar></Navbar>
      <h1 className="text-center dark:text-white font-extrabold text-3xl mx-auto mt-20 animate-slide-in">
        Explore the legal terrain of wallets!{" "}
      </h1>
      <br></br>
      <p className="text-center dark:text-white font-bold text-xl mx-auto mt-25">
        {" "}
        Enter a wallet ID to quickly determine its legal status.
      </p>
      <br></br>
      <div className="text-center dark:text-black font-bold text-lg">
        <div className="flex justify-center">
          <div className="w-2/4">
            <input
              type="text"
              value={inputValue}
              onChange={handleInputChange}
              className="border p-3 rounded-md w-full"
              placeholder="Enter Wallet id"
            />
          </div>
          <button
            className="bg-bluish-black ml-4 text-white text-lg px-3 py-3 rounded-md transition-all duration-300 transform hover:scale-110"
            onClick={handleSubmit}
          >
            Submit
          </button>
          <div className=" mt-11">
            {submitted && legalStatus !== null && (
              <ResultDisplay inputValue={legalStatus} />
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
