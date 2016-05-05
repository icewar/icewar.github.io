module Jekyll
  class Post
    EXCERPT_ATTRIBUTES_FOR_LIQUID = %w[
      title
      url
      date
      id
      categories
      next
      previous
      tags
      path
      langs
    ]

    def langs
      self.data.fetch("langs", [])
    end
  end
end
