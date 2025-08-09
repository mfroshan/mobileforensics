const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

exports.getHistory = async (req, res) => {
  const history = await prisma.scan.findMany({ orderBy: { uploadedAt: 'desc' } });
  res.json(history);
};
