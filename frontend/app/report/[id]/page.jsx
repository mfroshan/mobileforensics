import axios from 'axios';

export default async function ReportPage({ params }) {
  const res = await axios.get(`http://localhost:4000/report/${params.id}`);
  const data = res.data;
  return (
    <main className="p-8">
      <h1 className="text-xl font-bold">Report for {data.filename}</h1>
      <pre className="mt-4 bg-gray-100 p-4 rounded">{JSON.stringify(data, null, 2)}</pre>
    </main>
  );
}