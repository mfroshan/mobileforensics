import axios from 'axios';

export const uploadScan = async (file: File) => {
  const formData = new FormData();
  formData.append('file', file);
  const res = await axios.post('http://localhost:4000/scan', formData);
  return res.data;
};
