export default function ResultDisplay ({ inputValue }){
  const determineLegalStatus = () => {
    return inputValue === true ? 'LEGAL\n This wallet is completely safe \n have a good day!!<3' : 'ILLEGAL\n Please Contact The Authorities ASAP\n @1800-123-500014.';
  };

  const legalStatus = determineLegalStatus();

  return (
    <div className=" text-2xl font-bold ">
      
      {legalStatus && <span className="whitespace-pre-lined text-green-400"
        >
        {legalStatus}
      </span>}
      {!legalStatus && <span className="whitespace-pre-lined text-red-300"
        >
        {legalStatus}
      </span>}
    </div>
  );
};


