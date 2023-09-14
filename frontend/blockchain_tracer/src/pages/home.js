import TransactionSearch from "../components/transactionSearch";
export default function Home(props) {

  return (
    <>
      <TransactionSearch setCurrentTransaction={props.setCurrentTransaction} />
    </>
  );
}
