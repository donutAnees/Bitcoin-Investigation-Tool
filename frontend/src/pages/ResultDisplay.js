export default function ResultDisplay ({ inputValue }){
  const determineLegalStatus = () => {
    console.log('Debug: inputValue', inputValue);
    return inputValue === '123' ? 'LEGAL\n This wallet is completely safe \n' : 'ILLEGAL\n Please Contact The Authorities ASAP\n @1800-123-500014.';
  };

  const legalStatus = determineLegalStatus();

  return (
    <div className=" text-2xl font-bold ">
      
      <span className={`whitespace-pre-line ${
        legalStatus === 'Legal' 
        ? 'text-green-500 '
        :'text-brightRed  '
        }`}
        >
        
        {legalStatus}
        
      </span>
    </div>
  );
};


