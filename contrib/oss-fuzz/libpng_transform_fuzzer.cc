#include <png.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 8 || !png_check_sig(data, 8)) return 0;

  png_image image;
  memset(&image, 0, sizeof(image));
  image.version = PNG_IMAGE_VERSION;

  png_bytep buf = NULL;
  png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
  if (!png_ptr) return 0;

  png_infop info_ptr = png_create_info_struct(png_ptr);
  if (!info_ptr) {
    png_destroy_read_struct(&png_ptr, NULL, NULL);
    return 0;
  }

  if (setjmp(png_jmpbuf(png_ptr))) {
    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    free(buf);
    return 0;
  }

  png_set_read_fn(png_ptr, (png_voidp)&data, [](png_structp png_ptr, png_bytep outBytes, png_size_t byteCountToRead) {
    png_bytep* input = (png_bytep*)png_get_io_ptr(png_ptr);
    memcpy(outBytes, *input, byteCountToRead);
    *input += byteCountToRead;
  });

  png_set_sig_bytes(png_ptr, 8);
  data += 8;
  size -= 8;

  png_read_info(png_ptr, info_ptr);

  // Apply transformations from pngtrans.c
  png_set_expand(png_ptr);
  png_set_palette_to_rgb(png_ptr);
  png_set_tRNS_to_alpha(png_ptr);
  png_set_gray_to_rgb(png_ptr);
  png_set_strip_alpha(png_ptr);
  png_set_filler(png_ptr, 0xFF, PNG_FILLER_AFTER);
  png_set_swap(png_ptr);
  png_set_packing(png_ptr);

  png_read_update_info(png_ptr, info_ptr);

  int height = png_get_image_height(png_ptr, info_ptr);
  int rowbytes = png_get_rowbytes(png_ptr, info_ptr);
  if (height <= 0 || rowbytes <= 0) {
    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    return 0;
  }

  buf = (png_bytep)malloc(height * rowbytes);
  if (!buf) {
    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    return 0;
  }

  png_bytep* row_pointers = (png_bytep*)malloc(height * sizeof(png_bytep));
  for (int i = 0; i < height; i++)
    row_pointers[i] = buf + i * rowbytes;

  png_read_image(png_ptr, row_pointers);
  png_read_end(png_ptr, NULL);

  free(row_pointers);
  free(buf);
  png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
  return 0;
}
