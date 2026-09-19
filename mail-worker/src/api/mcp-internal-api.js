import app from '../hono/hono';
import BizError from '../error/biz-error';
import orm from '../entity/orm';
import email from '../entity/email';
import userService from '../service/user-service';
import accountService from '../service/account-service';
import emailService from '../service/email-service';
import { emailConst, isDel } from '../const/entity-const';
import { and, desc, eq, like, or } from 'drizzle-orm';

const INTERNAL_HEADER = 'X-MCP-Internal-Secret';

async function getMcpUser(c) {
	const user = await userService.selectByEmailIncludeDel(c, c.env.admin);
	if (!user || user.isDel === isDel.DELETE) {
		throw new BizError('MCP admin user is not available', 503);
	}
	return user;
}

app.use('/internal/mcp/*', async (c, next) => {
	const expected = c.env.MCP_INTERNAL_SECRET;
	const supplied = c.req.header(INTERNAL_HEADER);
	if (!expected || !supplied || supplied !== expected) {
		throw new BizError('Unauthorized MCP internal request', 401);
	}
	return next();
});

app.get('/internal/mcp/profile', async (c) => {
	const user = await getMcpUser(c);
	return c.json({
		userId: user.userId,
		email: user.email,
		isAdmin: user.email === c.env.admin
	});
});

app.get('/internal/mcp/accounts', async (c) => {
	const user = await getMcpUser(c);
	const list = await accountService.list(c, { size: 30 }, user.userId);
	return c.json(list.map(item => ({
		accountId: item.accountId,
		email: item.email,
		name: item.name,
		isPrimary: item.email === user.email
	})));
});

app.get('/internal/mcp/emails', async (c) => {
	const user = await getMcpUser(c);
	const params = c.req.query();
	const limit = Math.min(Math.max(Number(params.limit) || 10, 1), 20);
	const accountId = Number(params.accountId) || 0;
	const type = params.type === 'send' ? emailConst.type.SEND : emailConst.type.RECEIVE;

	const filters = [
		eq(email.userId, user.userId),
		eq(email.isDel, isDel.NORMAL),
		eq(email.type, type)
	];
	if (accountId) filters.push(eq(email.accountId, accountId));

	const rows = await orm(c).select({
		emailId: email.emailId,
		accountId: email.accountId,
		sendEmail: email.sendEmail,
		name: email.name,
		subject: email.subject,
		toEmail: email.toEmail,
		recipient: email.recipient,
		text: email.text,
		unread: email.unread,
		createTime: email.createTime,
		status: email.status
	}).from(email)
		.where(and(...filters))
		.orderBy(desc(email.emailId))
		.limit(limit)
		.all();

	return c.json(rows.map(row => ({
		...row,
		preview: (row.text || '').replace(/\s+/g, ' ').trim().slice(0, 500),
		text: undefined
	})));
});

app.get('/internal/mcp/email/:emailId', async (c) => {
	const user = await getMcpUser(c);
	const emailId = Number(c.req.param('emailId'));
	if (!emailId) throw new BizError('Invalid emailId', 400);

	const row = await emailService.selectById(c, emailId);
	if (!row || row.userId !== user.userId) {
		throw new BizError('Email not found', 404);
	}

	return c.json(row);
});

app.get('/internal/mcp/search', async (c) => {
	const user = await getMcpUser(c);
	const params = c.req.query();
	const query = (params.q || '').trim();
	if (!query) throw new BizError('Search query is required', 400);

	const limit = Math.min(Math.max(Number(params.limit) || 10, 1), 20);
	const accountId = Number(params.accountId) || 0;
	const typeFilter = params.type === 'send'
		? eq(email.type, emailConst.type.SEND)
		: params.type === 'receive'
			? eq(email.type, emailConst.type.RECEIVE)
			: undefined;
	const pattern = `%${query}%`;

	const filters = [
		eq(email.userId, user.userId),
		eq(email.isDel, isDel.NORMAL),
		typeFilter,
		accountId ? eq(email.accountId, accountId) : undefined,
		or(
			like(email.subject, pattern),
			like(email.sendEmail, pattern),
			like(email.toEmail, pattern),
			like(email.name, pattern),
			like(email.text, pattern)
		)
	].filter(Boolean);

	const rows = await orm(c).select({
		emailId: email.emailId,
		accountId: email.accountId,
		sendEmail: email.sendEmail,
		name: email.name,
		subject: email.subject,
		toEmail: email.toEmail,
		recipient: email.recipient,
		text: email.text,
		type: email.type,
		createTime: email.createTime
	}).from(email)
		.where(and(...filters))
		.orderBy(desc(email.emailId))
		.limit(limit)
		.all();

	return c.json(rows.map(row => ({
		...row,
		preview: (row.text || '').replace(/\s+/g, ' ').trim().slice(0, 500),
		text: undefined
	})));
});

app.post('/internal/mcp/send', async (c) => {
	const user = await getMcpUser(c);
	const body = await c.req.json();
	if (!Array.isArray(body.receiveEmail) || body.receiveEmail.length === 0) {
		throw new BizError('At least one recipient is required', 400);
	}

	const result = await emailService.send(c, {
		accountId: Number(body.accountId),
		name: body.name,
		receiveEmail: body.receiveEmail,
		subject: body.subject || '',
		text: body.text || '',
		content: body.content || body.text || '',
		attachments: []
	}, user.userId);

	return c.json(result);
});

app.post('/internal/mcp/reply', async (c) => {
	const user = await getMcpUser(c);
	const body = await c.req.json();
	const source = await emailService.selectById(c, Number(body.emailId));
	if (!source || source.userId !== user.userId) {
		throw new BizError('Email not found', 404);
	}

	const recipient = source.sendEmail;
	if (!recipient) throw new BizError('Original sender is unavailable', 400);

	const subject = body.subject || (source.subject?.toLowerCase().startsWith('re:')
		? source.subject
		: `Re: ${source.subject || ''}`);

	const result = await emailService.send(c, {
		accountId: Number(body.accountId) || source.accountId,
		name: body.name,
		sendType: 'reply',
		emailId: source.emailId,
		receiveEmail: [recipient],
		subject,
		text: body.text || '',
		content: body.content || body.text || '',
		attachments: []
	}, user.userId);

	return c.json(result);
});
