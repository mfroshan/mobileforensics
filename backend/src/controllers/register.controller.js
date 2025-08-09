const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

exports.handleRegister = async (req, res) => {
  const { name, email } = req.body;
  if (!name || !email) {
    return res.status(400).json({ error: "Name and email required" });
  }

  const existingUser = await prisma.user.findUnique({ where: { email } });
  if (existingUser) {
    return res.status(409).json({ error: "User already exists" });
  }

  const user = await prisma.user.create({
    data: { name, email }
  });

  res.json({ success: true, user });
};