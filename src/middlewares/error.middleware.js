export function notFoundHandler(req, res, next) {
  const error = new Error(`Route not found: ${req.originalUrl}`);
  error.statusCode = 404;
  next(error);
}

export function errorHandler(error, req, res, next) {
  const statusCode = error.statusCode || 500;

  if (req.originalUrl.startsWith("/api")) {
    return res.status(statusCode).json({
      ok: false,
      message: error.message || "Internal server error"
    });
  }

  return res.status(statusCode).render("pages/error", {
    title: "Error",
    statusCode,
    message: error.message || "Internal server error"
  });
}