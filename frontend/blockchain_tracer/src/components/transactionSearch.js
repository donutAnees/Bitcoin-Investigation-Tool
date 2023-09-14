import { useRef } from "react";
import styles from "./transactionSearch.module.css"
import { useNavigate } from "react-router-dom";

export default function TransactionSearch(props) {
  const inputRef = useRef();
  const navigate = useNavigate();

  const submitHandler = (e) => {
    e.preventDefault();
    navigate(`/transaction/${inputRef.current.value}`);
  }

  return (
    <form onSubmit={submitHandler}>
      <input
        className={styles.searchContainer}
        type="text"
        placeholder="Enter Transaction..."
        ref={inputRef}
      />
    </form>
  );
}
