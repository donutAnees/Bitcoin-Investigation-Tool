import TransactionSearch from "../components/transactionSearch";
export default function Graph(props) {

  return (
    <>
      <TransactionSearch setCurrentTransaction={props.setCurrentTransaction} />
    </>
  );
}
