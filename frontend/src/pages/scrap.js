import React, { useState } from 'react';
import Navbar from "../components/navbar";


export default function Scrap(){
const [walletId, setWalletId] = useState('');
const [result, setResult] = useState('');
const [website, setWebsite] = useState('');

const handleCheckWallet = async () => {
    try {
        const response = await fetch("http://127.0.0.1:5000/" + "walletavail?id=" + walletId)
        const {availability,website} = await response.json();
        
        console.log('Wallet ID to Check:', walletId);
        console.log('Wallet Found:', availability);

        if (availability) {
            setResult('Wallet found');
            setWebsite(website);
        } else {
            setResult('Wallet not found');
            setWebsite('');
        }
        
        } catch (error) {
        console.error('Error reading CSV file:', error);
        setResult('Error reading CSV file');
        }
    };

return (
<div className="bg-slate-50 dark:bg-bluish-black h-screen bg-light-bg dark:bg-dark-bg absolute bg-cover w-screen">
    <Navbar></Navbar>
    <div className="text-center dark:text-white font-bold text-lg">
        <h1 className="text-center dark:text-white font-extrabold text-3xl mx-auto mt-20 animate-slide-in">Wallet Checker</h1>
        <input
            type="text"
            placeholder="Enter Wallet ID"
            className="w-full p-2 mb-4 text-black border border-gray-300 rounded"
            value={walletId}
            onChange={(e) => setWalletId(e.target.value)}
            />
            <button
            className="bg-bluish-black text-white text-lg px-5 py-4 rounded-md transition-all duration-300 transform hover:scale-110"
            onClick={handleCheckWallet}
            >
            Check Wallet
            </button>
            <div className="mt-4">{result && <p className="text-sm">{result}</p>}
            {website && <p className="text-sm">Website: <a href={website} target="_blank" rel="noopener noreferrer"> {website}</a></p>}
            </div>
        </div>
    </div>
    );
}