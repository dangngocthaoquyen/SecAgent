from pydantic import BaseModel

class PayloadTemplate(BaseModel):
    id: str
    name: str
    category: str
    template: str