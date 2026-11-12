class ThumbnailJob < ApplicationJob
  def perform(path, size)
    system("convert #{path} -resize #{size} out.png")
  end
end
