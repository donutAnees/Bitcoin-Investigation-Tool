import Navbar from "../components/navbar";
import React, { useState } from 'react';
import ResultDisplay from './ResultDisplay';
export default function Wallet() {

    const [inputValue, setInputValue] = useState('');
    const [submitted, setSubmitted] = useState(false);
    const [legalStatus, setLegalStatus] = useState(null);
    const handleInputChange = (event) => {
      const value = event.target.value;
      setInputValue(value);
    if (value === '') {
      setSubmitted(false);
      setLegalStatus(null);
      }
    };
    const handleSubmit = () => {
      setLegalStatus(inputValue === 'legal' ? 'Legal' : 'Illegal');
      setSubmitted(true);
    };
  
  return (
    <div className="bg-purple-bg purple:bg-purple-bg h-screen bg-cover w-screen relative">
        <Navbar></Navbar>
      <h1 className="text-center dark:text-white font-extrabold text-3xl mx-auto mt-20 animate-slide-in">

      Explore the legal terrain of wallets! </h1><br></br>
      <p className="text-center dark:text-white font-bold text-xl mx-auto mt-25"> Enter a wallet ID to quickly determine its legal status and ensure a secure and compliant financial experience.</p>
      <br></br>     
      <div className="text-center dark:text-black font-bold">
        <div className="container mx-auto mt-10 text-center ">
        <input
          type="text"
          value={inputValue}
          onChange={handleInputChange}
          className="border p-2 mb-4 rounded-md"
          placeholder="Enter Wallet id"
        />
        <button className="bg-purple-bg purple:bg-purple-bg text-white px-3.5 py-2.5 rounded-md transition-all duration-300 transform hover:scale-110"onClick={handleSubmit}>
        Submit
        </button>

        {submitted && legalStatus !== null && (
        <ResultDisplay legalStatus={legalStatus} />
      )}
      </div>
      </div>
    </div>
  );
};
