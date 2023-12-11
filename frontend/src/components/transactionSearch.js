import { useRef } from "react";
import { useNavigate } from "react-router-dom";

export default function TransactionSearch(props) {
  const inputRef = useRef();
  const navigate = useNavigate();

  const submitHandler = (e) => {
    e.preventDefault();
    navigate(`/transaction/${inputRef.current.value}`);
  };

  return (
    <div className="mx-auto w-3/4 pt-10">
      <form onSubmit={submitHandler}>
        <input
          className="w-full rounded-lg p-1"
          type="text"
          placeholder="Enter Transaction..."
          ref={inputRef}
        />
      </form>
    </div>
  );
}
