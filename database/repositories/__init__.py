"""One repository class per MongoDB collection. Application code talks to these, never to raw collections."""
from database.repositories.base import DocumentRejected, DuplicateRecord, NotFound   # noqa: F401
from database.repositories.repos import (ConversationsRepository, DocumentMetadataRepository, FeedbackRepository,  # noqa: F401
                                         JobsRepository, MessagesRepository, ReportsRepository, TracesRepository,
                                         UsersRepository, Repositories)
