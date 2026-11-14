variable "lb_stream_idle_timeout_ms" {
  description = "Maximum idle time of an active HTTP stream in milliseconds; null uses the platform default."
  type        = number
  default     = null
  validation {
    condition     = var.lb_stream_idle_timeout_ms == null ? true : var.lb_stream_idle_timeout_ms > 0
    error_message = "Stream idle timeout must be positive."
  }
}
