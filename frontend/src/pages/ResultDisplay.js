export default function ResultDisplay ({ inputValue }){
  const determineLegalStatus = () => {
    console.log('Debug: inputValue', inputValue);
    return inputValue === 'legal' ? 'LEGAL\n This wallet is completely safe \n have a good day!!<3' : 'ILLEGAL\n please contact the authorities ASAP\n  1800-123-500014.';
  };

  const legalStatus = determineLegalStatus();

  return (
    <div className=" text-xl font-bold ">
      
      <span className={`whitespace-pre-line ${
        legalStatus === 'Legal' 
        ? 'text-green-500 drop-shadow-xl '
        :'text-brightRed drop-shadow-2xl '
        }`}
        >
        
        {legalStatus}
        
      </span>
    </div>
  );
};


