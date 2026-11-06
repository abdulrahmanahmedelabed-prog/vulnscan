class Note < ApplicationRecord
end
class NotesController < ApplicationController
  def create
    Note.create(body: params[:body], title: "t")
  end
  def show
    n = Note.find(params[:id])
    system("echo #{n.body}")
    system("echo #{n.title}")
  end
end
