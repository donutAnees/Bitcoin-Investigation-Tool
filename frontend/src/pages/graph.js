import TransactionSearch from "../components/transactionSearch";
export default function Graph(props) {
  return (
    <div className="h-screen dark:bg-bluish-black bg-slate-50 bg-cover bg-light-bg dark:bg-dark-bg">
        <TransactionSearch
          setCurrentTransaction={props.setCurrentTransaction}
        />
    </div>
  );
}
